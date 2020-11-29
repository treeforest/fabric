/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package algo

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric/gossip/util"
)

/* PullEngine is an object that performs pull-based gossip, and maintains an internal state of items
   identified by string numbers.
   The protocol is as follows:
   1) The Initiator sends a Hello message with a specific NONCE to a set of remote peers.
   2) Each remote peer responds with a digest of its messages and returns that NONCE.
   3) The initiator checks the validity of the NONCEs received, aggregates the digests,
      and crafts a request containing specific item ids it wants to receive from each remote peer and then
      sends each request to its corresponding peer.
   4) Each peer sends back the response containing the items requested, if it still holds them and the NONCE.

    Other peer				   			   Initiator
	 O	<-------- Hello <NONCE> -------------------------	O
	/|\	--------- Digest <[3,5,8, 10...], NONCE> --------> /|\
	 |	<-------- Request <[3,8], NONCE> -----------------  |
	/ \	--------- Response <[item3, item8], NONCE>-------> / \

*/

/* PullEngine 是一个基于gossip的pull执行对象，维护一个由字符串标识的元素的内部状态。
其协议如下：
1）发起者发送一个带有特定 NONCE 值的 Hello 消息给一组远程节点。
2）每个远程节点都其消息摘要响应，并返回该 NONCE。
3）发起者检查所有收到的 NONCE 的有效性，聚合所有摘要，并构造一个包含它希望从远
	程节点获取的所有元素ID的请求包（request），然后将该请求包发送给对应节点。
4）每个节点都返回一个包含请求元素的响应（response）。前提是，这些节点保留有所
	请求元素的信息以及 NONCE 值。
*/

const (
	DefDigestWaitTime   = 1000 * time.Millisecond
	DefRequestWaitTime  = 1500 * time.Millisecond
	DefResponseWaitTime = 2000 * time.Millisecond
)

// DigestFilter filters digests to be sent to a remote peer that
// sent a hello or a request, based on its messages's context
// 筛选发送给远程节点的摘要。可能是hello或request摘要，具体根据消息的上下文判断。
type DigestFilter func(context interface{}) func(digestItem string) bool

// PullAdapter is needed by the PullEngine in order to
// send messages to the remote PullEngine instances.
// The PullEngine expects to be invoked with
// OnHello, OnDigest, OnReq, OnRes when the respective message arrives
// from a remote PullEngine
// PullEngine 使用 PullAdapter 发送消息给远程 PullEngine 实例。
// 当相应的消息从远程 PullEngine 到来时，PullEngine 将会调用OnHello,
// OnDigest, OnReq, OnRes
type PullAdapter interface {
	// SelectPeers returns a slice of peers which the engine will initiate the protocol with
	// 返回peer节点的切片，PullEngine将使用它来初始化协议
	SelectPeers() []string

	// Hello sends a hello message to initiate the protocol
	// and returns an NONCE that is expected to be returned
	// in the digest message.
	// 发送一个Hello消息来初始化协议，并返回一个被期望在摘要
	// 信息中返回的 NONCE 值
	Hello(dest string, nonce uint64)

	// SendDigest sends a digest to a remote PullEngine.
	// The context parameter specifies the remote engine to send to.
	// 发送一个摘要给远程PullEngine。
	// context 参数指定要发送到的远程引擎。
	SendDigest(digest []string, nonce uint64, context interface{})

	// SendReq sends an array of items to a certain remote PullEngine identified
	// by a string
	// 发送 items 到一个由 dest 指定地址的远程 PullEngine
	SendReq(dest string, items []string, nonce uint64)

	// SendRes sends an array of items to a remote PullEngine identified by a context.
	// 发送 items 到一个由 context 指定地址的远程 PullEngine
	SendRes(items []string, context interface{}, nonce uint64)
}

// PullEngine is the component that actually invokes the pull algorithm
// with the help of the PullAdapter
// PullEngine 是在 PullAdapter 的帮助下实际调用 pull 算法的组件
type PullEngine struct {
	PullAdapter                    // pull 适配器
	stopFlag           int32               // 停止标志
	state              *util.Set           // 保存消息摘要的集合，其线程安全
	item2owners        map[string][]string // item所对应拥有该item的拥有者集合
	peers2nonces       map[string]uint64   // <endpoint, nonce> endpoint: 端点地址
	nonces2peers       map[uint64]string   // <nonce, endpoint>
	acceptingDigests   int32               // 正在接收摘要
	acceptingResponses int32               // 正在接收回复
	lock               sync.Mutex
	outgoingNONCES     *util.Set
	incomingNONCES     *util.Set
	digFilter          DigestFilter	// 摘要过滤器

	digestWaitTime   time.Duration
	requestWaitTime  time.Duration
	responseWaitTime time.Duration
}

// PullEngineConfig is the configuration required to initialize a new pull engine
// PullEngineConfig 是初始化一个pull引擎的所需要的配置
type PullEngineConfig struct {
	DigestWaitTime   time.Duration // 摘要等待时间
	RequestWaitTime  time.Duration // 请求等待时间
	ResponseWaitTime time.Duration // 响应等待时间
}

// NewPullEngineWithFilter creates an instance of a PullEngine with a certain sleep time
// between pull initiations, and uses the given filters when sending digests and responses
func NewPullEngineWithFilter(participant PullAdapter, sleepTime time.Duration, df DigestFilter,
	config PullEngineConfig) *PullEngine {
	engine := &PullEngine{
		PullAdapter:        participant,
		stopFlag:           int32(0),
		state:              util.NewSet(),
		item2owners:        make(map[string][]string),
		peers2nonces:       make(map[string]uint64),
		nonces2peers:       make(map[uint64]string),
		acceptingDigests:   int32(0),
		acceptingResponses: int32(0),
		incomingNONCES:     util.NewSet(),
		outgoingNONCES:     util.NewSet(),
		digFilter:          df,
		digestWaitTime:     config.DigestWaitTime,
		requestWaitTime:    config.RequestWaitTime,
		responseWaitTime:   config.ResponseWaitTime,
	}

	go func() {
		for !engine.toDie() {
			time.Sleep(sleepTime)
			if engine.toDie() {
				return
			}
			engine.initiatePull()
		}
	}()

	return engine
}

// NewPullEngine creates an instance of a PullEngine with a certain sleep time
// between pull initiations
func NewPullEngine(participant PullAdapter, sleepTime time.Duration, config PullEngineConfig) *PullEngine {
	acceptAllFilter := func(_ interface{}) func(string) bool {
		return func(_ string) bool {
			return true
		}
	}
	return NewPullEngineWithFilter(participant, sleepTime, acceptAllFilter, config)
}

func (engine *PullEngine) toDie() bool {
	return atomic.LoadInt32(&(engine.stopFlag)) == int32(1)
}

func (engine *PullEngine) acceptResponses() {
	atomic.StoreInt32(&(engine.acceptingResponses), int32(1))
}

func (engine *PullEngine) isAcceptingResponses() bool {
	return atomic.LoadInt32(&(engine.acceptingResponses)) == int32(1)
}

func (engine *PullEngine) acceptDigests() {
	atomic.StoreInt32(&(engine.acceptingDigests), int32(1))
}

func (engine *PullEngine) isAcceptingDigests() bool {
	return atomic.LoadInt32(&(engine.acceptingDigests)) == int32(1)
}

func (engine *PullEngine) ignoreDigests() {
	atomic.StoreInt32(&(engine.acceptingDigests), int32(0))
}

// Stop stops the engine
func (engine *PullEngine) Stop() {
	atomic.StoreInt32(&(engine.stopFlag), int32(1))
}

func (engine *PullEngine) initiatePull() {
	engine.lock.Lock()
	defer engine.lock.Unlock()

	// 1、发送Hello消息
	engine.acceptDigests()
	for _, peer := range engine.SelectPeers() {
		nonce := engine.newNONCE()        // 获取一个唯一的nonce值
		engine.outgoingNONCES.Add(nonce)  // 保存发送的nonce
		engine.nonces2peers[nonce] = peer // 记录nonce所对应的peer（注：这里的peer指的是节点对应的地址）
		engine.peers2nonces[peer] = nonce // 记录peer所对应的nonce
		engine.Hello(peer, nonce)         // 向peer发送Hello消息
	}

	// 2、在 digestWaitTime 时间后开始调用processIncomingDigests，对到来Digest进行处理
	time.AfterFunc(engine.digestWaitTime, func() {
		engine.processIncomingDigests()
	})
}

// processIncomingDigests 处理到来的摘要
func (engine *PullEngine) processIncomingDigests() {
	engine.ignoreDigests() // 忽略接下来收到的 Digest

	engine.lock.Lock() // lock
	defer engine.lock.Unlock()

	// 1、组装待发送的 request 的内容
	requestMapping := make(map[string][]string)
	for n, sources := range engine.item2owners {
		// 随机选择一个源(摘要拥有者)
		source := sources[util.RandomInt(len(sources))]
		if _, exists := requestMapping[source]; !exists {
			requestMapping[source] = make([]string, 0)
		}
		// append the number to that source
		requestMapping[source] = append(requestMapping[source], n)
	}

	// 2、允许OnRest处理 Response 消息
	engine.acceptResponses()

	// 3、发送 Request 消息
	for dest, seqsToReq := range requestMapping {
		engine.SendReq(dest, seqsToReq, engine.peers2nonces[dest])
	}

	// 4、在responseWaitTime时间后调用endPull
	time.AfterFunc(engine.responseWaitTime, engine.endPull)
}

func (engine *PullEngine) endPull() {
	engine.lock.Lock()
	defer engine.lock.Unlock()

	atomic.StoreInt32(&(engine.acceptingResponses), int32(0))
	engine.outgoingNONCES.Clear()

	engine.item2owners = make(map[string][]string)
	engine.peers2nonces = make(map[string]uint64)
	engine.nonces2peers = make(map[uint64]string)
}

// OnDigest notifies the engine that a digest has arrived
// OnDigest 通知引擎一个摘要已经到达
func (engine *PullEngine) OnDigest(digest []string, nonce uint64, context interface{}) {
	// 1、若正在接收摘要或不存在该nonce，则直接返回
	if !engine.isAcceptingDigests() || !engine.outgoingNONCES.Exists(nonce) {
		return
	}

	engine.lock.Lock()
	defer engine.lock.Unlock()

	// 2、由获取到的摘要信息，筛选出自身缺失的摘要后将nonce保存，便于后续请求缺失的摘要。
	for _, n := range digest {
		if engine.state.Exists(n) { // 是否已存在该摘要
			continue
		}

		if _, exists := engine.item2owners[n]; !exists {
			engine.item2owners[n] = make([]string, 0) // 初始化
		}

		// 将拥有该摘要的节点所对应的nonce值保存
		engine.item2owners[n] = append(engine.item2owners[n], engine.nonces2peers[nonce])
	}
}

// Add adds items to the state
func (engine *PullEngine) Add(seqs ...string) {
	for _, seq := range seqs {
		engine.state.Add(seq)
	}
}

// Remove removes items from the state
func (engine *PullEngine) Remove(seqs ...string) {
	for _, seq := range seqs {
		engine.state.Remove(seq)
	}
}

// OnHello notifies the engine a hello has arrived
// OnHello 通知引擎一个 hello 已经到达
func (engine *PullEngine) OnHello(nonce uint64, context interface{}) {
	// 1、将 nonce 记录到 incomingNONCES
	engine.incomingNONCES.Add(nonce)

	// 2、若是在 requestWaitTime 时间内没有收到 request，则移除 nonce
	time.AfterFunc(engine.requestWaitTime, func() {
		engine.incomingNONCES.Remove(nonce)
	})

	// 3、获取所有保存在集合中的消息摘要
	a := engine.state.ToArray()

	// 4、由filter筛选出所有符合要求的摘要(digest)
	var digest []string
	filter := engine.digFilter(context)
	for _, item := range a {
		dig := item.(string)
		if !filter(dig) {
			continue
		}
		digest = append(digest, dig)
	}

	// 5、交由PullAdapter发送摘要信息
	if len(digest) == 0 {
		return
	}
	engine.SendDigest(digest, nonce, context)
}

// OnReq notifies the engine a request has arrived
// OnReq 处理到达的 request 消息
func (engine *PullEngine) OnReq(items []string, nonce uint64, context interface{}) {
	if !engine.incomingNONCES.Exists(nonce) { // 是否保存交互的nonce值
		return
	}
	engine.lock.Lock()
	defer engine.lock.Unlock()

	// 1、筛选远程节点请求的元素(即消息摘要)，并将元素加入待发送序列(items2Send)中
	filter := engine.digFilter(context)
	var items2Send []string
	for _, item := range items {
		if engine.state.Exists(item) && filter(item) {
			items2Send = append(items2Send, item)
		}
	}

	if len(items2Send) == 0 {
		return
	}

	// 2、异步发送响应消息
	go engine.SendRes(items2Send, context, nonce)
}

// OnRes notifies the engine a response has arrived
// OnRes 通知引擎一个响应已经到达
func (engine *PullEngine) OnRes(items []string, nonce uint64) {
	if !engine.outgoingNONCES.Exists(nonce) || !engine.isAcceptingResponses() {
		return
	}

	engine.Add(items...)
}

// 返回一个随机不重复的uint64类型的NONCE值
func (engine *PullEngine) newNONCE() uint64 {
	n := uint64(0)
	for {
		n = util.RandomUInt64()
		if !engine.outgoingNONCES.Exists(n) {
			return n
		}
	}
}
