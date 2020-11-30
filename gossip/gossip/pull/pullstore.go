/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pull

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/hyperledger/fabric-protos-go/gossip"
	proto "github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric/gossip/comm"
	"github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/gossip/discovery"
	"github.com/hyperledger/fabric/gossip/gossip/algo"
	"github.com/hyperledger/fabric/gossip/protoext"
	"github.com/hyperledger/fabric/gossip/util"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
)

// Constants go here.
const (
	HelloMsgType MsgType = iota
	DigestMsgType
	RequestMsgType
	ResponseMsgType
)

// MsgType defines the type of a message that is sent to the PullStore
type MsgType int

// MessageHook defines a function that will run after a certain pull message is received
type MessageHook func(itemIDs []string, items []*protoext.SignedGossipMessage, msg protoext.ReceivedMessage)

// Sender sends messages to remote peers
type Sender interface {
	// Send sends a message to a list of remote peers
	Send(msg *protoext.SignedGossipMessage, peers ...*comm.RemotePeer)
}

// MembershipService obtains membership information of alive peers
type MembershipService interface {
	// GetMembership returns the membership of
	GetMembership() []discovery.NetworkMember
}

// Config defines the configuration of the pull mediator
type Config struct {
	ID                string                  // 配置ID
	PullInterval      time.Duration           // 拉取引擎pull间隔时间
	Channel           common.ChannelID        // 链ID，在GossipMessage中填写
	PeerCountToSelect int                     // 拉取引擎每次pull时选取的节点数
	Tag               proto.GossipMessage_Tag // 消息标签，在GossipMessage中填写
	MsgType           proto.PullMsgType       // 拉取的消息类型
	PullEngineConfig  algo.PullEngineConfig   // 拉取引擎配置
}

// IngressDigestFilter filters out entities in digests that are received from remote peers
type IngressDigestFilter func(digestMsg *proto.DataDigest) *proto.DataDigest

// EgressDigestFilter filters digests to be sent to a remote peer, that
// sent a hello with the following message
type EgressDigestFilter func(helloMsg protoext.ReceivedMessage) func(digestItem string) bool

// byContext converts this EgressDigFilter to an algo.DigestFilter
func (df EgressDigestFilter) byContext() algo.DigestFilter {
	return func(context interface{}) func(digestItem string) bool {
		return func(digestItem string) bool {
			return df(context.(protoext.ReceivedMessage))(digestItem)
		}
	}
}

// MsgConsumer invokes code given a SignedGossipMessage
type MsgConsumer func(message *protoext.SignedGossipMessage)

// IdentifierExtractor extracts from a SignedGossipMessage an identifier
type IdentifierExtractor func(*protoext.SignedGossipMessage) string

// PullAdapter 定义pullStore与gossip的各个模块交互的方法
type PullAdapter struct {
	Sndr             Sender              // 向远程peer节点发送消息
	MemSvc           MembershipService   // 获取alive节点的成员信息
	IdExtractor      IdentifierExtractor // 从SignedGossipMessage中提取一个标识符(identifier)
	MsgCons          MsgConsumer         // 消费者，处理SignedGossipMessage消息
	EgressDigFilter  EgressDigestFilter  // 发出消息过滤器
	IngressDigFilter IngressDigestFilter // 到来消息过滤器
}

// Mediator is a component wrap a PullEngine and provides the methods
// it needs to perform pull synchronization.
// The specialization of a pull mediator to a certain type of message is
// done by the configuration, a IdentifierExtractor, IdentifierExtractor
// given at construction, and also hooks that can be registered for each
// type of pullMsgType (hello, digest, req, res).
type Mediator interface {
	// Stop 停止Mediator运行
	Stop()

	// RegisterMsgHook 将消息钩子注册到特定类型的pull消息
	RegisterMsgHook(MsgType, MessageHook)

	// Add 添加一个Gossip消息(GossipMessage)到Mediator
	Add(*protoext.SignedGossipMessage)

	// Remove 根据消息摘要(digest)从Mediator中移除消息(GossipMessage)
	Remove(digest string)

	// HandleMessage 处理来自某个远程peer的消息
	HandleMessage(msg protoext.ReceivedMessage)
}

// pullMediatorImpl is an implementation of Mediator
type pullMediatorImpl struct {
	sync.RWMutex
	*PullAdapter                                         // 拉取适配器
	msgType2Hook map[MsgType][]MessageHook                // <消息类型，对该消息类型所注册的钩子函数>
	config       Config                                   // 配置文件
	logger       util.Logger                              // 日志打印
	itemID2Msg   map[string]*protoext.SignedGossipMessage // <消息摘要，具体消息>
	engine       *algo.PullEngine                         // 拉取引擎
}

// NewPullMediator returns a new Mediator
func NewPullMediator(config Config, adapter *PullAdapter) Mediator {
	egressDigFilter := adapter.EgressDigFilter

	acceptAllFilter := func(_ protoext.ReceivedMessage) func(string) bool {
		return func(_ string) bool {
			return true
		}
	}

	if egressDigFilter == nil {
		egressDigFilter = acceptAllFilter
	}

	p := &pullMediatorImpl{
		PullAdapter:  adapter,
		msgType2Hook: make(map[MsgType][]MessageHook),
		config:       config,
		logger:       util.GetLogger(util.PullLogger, config.ID),
		itemID2Msg:   make(map[string]*protoext.SignedGossipMessage),
	}

	// 初始化拉取引擎
	p.engine = algo.NewPullEngineWithFilter(p, config.PullInterval, egressDigFilter.byContext(), config.PullEngineConfig)

	if adapter.IngressDigFilter == nil {
		// Create accept all filter
		adapter.IngressDigFilter = func(digestMsg *proto.DataDigest) *proto.DataDigest {
			return digestMsg
		}
	}
	return p

}

func (p *pullMediatorImpl) HandleMessage(m protoext.ReceivedMessage) {
	if m.GetGossipMessage() == nil || !protoext.IsPullMsg(m.GetGossipMessage().GossipMessage) {
		return
	}

	// 1、若不是配置中指定的消息类型，则直接返回
	msg := m.GetGossipMessage()
	msgType := protoext.GetPullMsgType(msg.GossipMessage)
	if msgType != p.config.MsgType {
		return
	}

	p.logger.Debug(msg)

	itemIDs := []string{}
	items := []*protoext.SignedGossipMessage{}
	var pullMsgType MsgType

	// 2、判断消息类型，并调用相应的处理
	if helloMsg := msg.GetHello(); helloMsg != nil { // Hello Message
		pullMsgType = HelloMsgType
		p.engine.OnHello(helloMsg.Nonce, m)
	} else if digest := msg.GetDataDig(); digest != nil { // Digest Message
		d := p.PullAdapter.IngressDigFilter(digest)
		itemIDs = util.BytesToStrings(d.Digests)
		pullMsgType = DigestMsgType
		p.engine.OnDigest(itemIDs, d.Nonce, m)
	} else if req := msg.GetDataReq(); req != nil { // Request Message
		itemIDs = util.BytesToStrings(req.Digests)
		pullMsgType = RequestMsgType
		p.engine.OnReq(itemIDs, req.Nonce, m)
	} else if res := msg.GetDataUpdate(); res != nil { // Response Message
		itemIDs = make([]string, len(res.Data))
		items = make([]*protoext.SignedGossipMessage, len(res.Data))
		pullMsgType = ResponseMsgType
		for i, pulledMsg := range res.Data {
			msg, err := protoext.EnvelopeToGossipMessage(pulledMsg)
			if err != nil {
				p.logger.Warningf("Data update contains an invalid message: %+v", errors.WithStack(err))
				return
			}
			p.MsgCons(msg)
			itemIDs[i] = p.IdExtractor(msg)
			items[i] = msg
			p.Lock()
			p.itemID2Msg[itemIDs[i]] = msg
			p.logger.Debugf("Added %s to the in memory item map, total items: %d", itemIDs[i], len(p.itemID2Msg))
			p.Unlock()
		}
		p.engine.OnRes(itemIDs, res.Nonce)
	}

	// 3、调用相关消息类型的钩子
	for _, h := range p.hooksByMsgType(pullMsgType) {
		h(itemIDs, items, m)
	}
}

func (p *pullMediatorImpl) Stop() {
	p.engine.Stop()
}

// RegisterMsgHook registers a message hook to a specific type of pull message
func (p *pullMediatorImpl) RegisterMsgHook(pullMsgType MsgType, hook MessageHook) {
	p.Lock()
	defer p.Unlock()
	// 此处没有进行判断重复性钩子注册
	p.msgType2Hook[pullMsgType] = append(p.msgType2Hook[pullMsgType], hook)

}

// Add adds a GossipMessage to the store
func (p *pullMediatorImpl) Add(msg *protoext.SignedGossipMessage) {
	p.Lock()
	defer p.Unlock()
	itemID := p.IdExtractor(msg)
	p.itemID2Msg[itemID] = msg
	p.engine.Add(itemID)
	p.logger.Debugf("Added %s, total items: %d", itemID, len(p.itemID2Msg))
}

// Remove removes a GossipMessage from the Mediator with a matching digest,
// if such a message exits
func (p *pullMediatorImpl) Remove(digest string) {
	p.Lock()
	defer p.Unlock()
	delete(p.itemID2Msg, digest)
	p.engine.Remove(digest)
	p.logger.Debugf("Removed %s, total items: %d", digest, len(p.itemID2Msg))
}

// SelectPeers returns a slice of peers which the engine will initiate the protocol with
func (p *pullMediatorImpl) SelectPeers() []string {
	remotePeers := SelectEndpoints(p.config.PeerCountToSelect, p.MemSvc.GetMembership())
	endpoints := make([]string, len(remotePeers))
	for i, peer := range remotePeers {
		endpoints[i] = peer.Endpoint
	}
	return endpoints
}

// Hello sends a hello message to initiate the protocol
// and returns an NONCE that is expected to be returned
// in the digest message.
func (p *pullMediatorImpl) Hello(dest string, nonce uint64) {
	helloMsg := &proto.GossipMessage{
		Channel: p.config.Channel,
		Tag:     p.config.Tag,
		Content: &proto.GossipMessage_Hello{
			Hello: &proto.GossipHello{
				Nonce:    nonce,
				Metadata: nil,
				MsgType:  p.config.MsgType,
			},
		},
	}

	p.logger.Debug("Sending", p.config.MsgType, "hello to", dest)
	sMsg, err := protoext.NoopSign(helloMsg)
	if err != nil {
		p.logger.Errorf("Failed creating SignedGossipMessage: %+v", errors.WithStack(err))
		return
	}
	p.Sndr.Send(sMsg, p.peersWithEndpoints(dest)...)
}

// SendDigest sends a digest to a remote PullEngine.
// The context parameter specifies the remote engine to send to.
func (p *pullMediatorImpl) SendDigest(digest []string, nonce uint64, context interface{}) {
	digMsg := &proto.GossipMessage{
		Channel: p.config.Channel,
		Tag:     p.config.Tag,
		Nonce:   0,
		Content: &proto.GossipMessage_DataDig{
			DataDig: &proto.DataDigest{
				MsgType: p.config.MsgType,
				Nonce:   nonce,
				Digests: util.StringsToBytes(digest),
			},
		},
	}
	remotePeer := context.(protoext.ReceivedMessage).GetConnectionInfo()
	if p.logger.IsEnabledFor(zapcore.DebugLevel) {
		p.logger.Debug("Sending", p.config.MsgType, "digest:", formattedDigests(digMsg.GetDataDig()), "to", remotePeer)
	}

	context.(protoext.ReceivedMessage).Respond(digMsg)
}

// SendReq sends an array of items to a certain remote PullEngine identified
// by a string
func (p *pullMediatorImpl) SendReq(dest string, items []string, nonce uint64) {
	req := &proto.GossipMessage{
		Channel: p.config.Channel,
		Tag:     p.config.Tag,
		Nonce:   0,
		Content: &proto.GossipMessage_DataReq{
			DataReq: &proto.DataRequest{
				MsgType: p.config.MsgType,
				Nonce:   nonce,
				Digests: util.StringsToBytes(items),
			},
		},
	}
	if p.logger.IsEnabledFor(zapcore.DebugLevel) {
		p.logger.Debug("Sending", formattedDigests(req.GetDataReq()), "to", dest)
	}
	sMsg, err := protoext.NoopSign(req)
	if err != nil {
		p.logger.Warningf("Failed creating SignedGossipMessage: %+v", errors.WithStack(err))
		return
	}
	p.Sndr.Send(sMsg, p.peersWithEndpoints(dest)...)
}

// typeDigster normalizes the common digest operations needed to format them
// for log messages.
type typedDigester interface {
	GetMsgType() gossip.PullMsgType
	GetDigests() [][]byte
}

func formattedDigests(dd typedDigester) []string {
	switch dd.GetMsgType() {
	case gossip.PullMsgType_IDENTITY_MSG:
		return digestsToHex(dd.GetDigests())
	default:
		return digestsAsStrings(dd.GetDigests())
	}
}

func digestsAsStrings(digests [][]byte) []string {
	a := make([]string, len(digests))
	for i, dig := range digests {
		a[i] = string(dig)
	}
	return a
}

func digestsToHex(digests [][]byte) []string {
	a := make([]string, len(digests))
	for i, dig := range digests {
		a[i] = hex.EncodeToString(dig)
	}
	return a
}

// SendRes sends an array of items to a remote PullEngine identified by a context.
func (p *pullMediatorImpl) SendRes(items []string, context interface{}, nonce uint64) {
	items2return := []*proto.Envelope{}
	p.RLock()
	defer p.RUnlock()
	for _, item := range items {
		if msg, exists := p.itemID2Msg[item]; exists {
			items2return = append(items2return, msg.Envelope)
		}
	}
	returnedUpdate := &proto.GossipMessage{
		Channel: p.config.Channel,
		Tag:     p.config.Tag,
		Nonce:   0,
		Content: &proto.GossipMessage_DataUpdate{
			DataUpdate: &proto.DataUpdate{
				MsgType: p.config.MsgType,
				Nonce:   nonce,
				Data:    items2return,
			},
		},
	}
	remotePeer := context.(protoext.ReceivedMessage).GetConnectionInfo()
	p.logger.Debug("Sending", len(returnedUpdate.GetDataUpdate().Data), p.config.MsgType, "items to", remotePeer)
	context.(protoext.ReceivedMessage).Respond(returnedUpdate)
}

func (p *pullMediatorImpl) peersWithEndpoints(endpoints ...string) []*comm.RemotePeer {
	peers := []*comm.RemotePeer{}
	for _, member := range p.MemSvc.GetMembership() {
		for _, endpoint := range endpoints {
			if member.PreferredEndpoint() == endpoint {
				peers = append(peers, &comm.RemotePeer{Endpoint: member.PreferredEndpoint(), PKIID: member.PKIid})
			}
		}
	}
	return peers
}

func (p *pullMediatorImpl) hooksByMsgType(msgType MsgType) []MessageHook {
	p.RLock()
	defer p.RUnlock()
	return append([]MessageHook(nil), p.msgType2Hook[msgType]...)
}

// SelectEndpoints select k peers from peerPool and returns them.
func SelectEndpoints(k int, peerPool []discovery.NetworkMember) []*comm.RemotePeer {
	if len(peerPool) < k {
		k = len(peerPool)
	}

	indices := util.GetRandomIndices(k, len(peerPool)-1)
	endpoints := make([]*comm.RemotePeer, len(indices))
	for i, j := range indices {
		endpoints[i] = &comm.RemotePeer{Endpoint: peerPool[j].PreferredEndpoint(), PKIID: peerPool[j].PKIid}
	}
	return endpoints
}
