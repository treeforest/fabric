/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gossip

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

type emitBatchCallback func([]interface{})

// batchingEmitter 被用于gossip的推送或转发阶段
// 消息被添加到batchingEmitter中，它们被周期性地分批转发T次，然后被丢弃。
// 如果batchingEmitter存储的消息计数达到一定的容量，那么也会触发消息转发。
type batchingEmitter interface {
	// Add 添加要批处理的消息
	Add(interface{})

	// Stop 停止组件
	Stop()

	// Size 返回要转发的挂起消息的数量
	Size() int
}

// newBatchingEmitter 接受以下参数:
// iterations: 每条消息被转发的次数
// burstSize: 由于消息计数而触发转发的阈值
// latency: 每条消息在不转发的情况下可以存储的最大延迟
// cb: 为了进行转发而调用的回调
func newBatchingEmitter(iterations, burstSize int, latency time.Duration, cb emitBatchCallback) batchingEmitter {
	if iterations < 0 {
		panic(errors.Errorf("Got a negative iterations number"))
	}

	p := &batchingEmitterImpl{
		cb:         cb,
		delay:      latency,
		iterations: iterations,
		burstSize:  burstSize,
		lock:       &sync.Mutex{},
		buff:       make([]*batchedMessage, 0),
		stopFlag:   int32(0),
	}

	if iterations != 0 {
		go p.periodicEmit()
	}

	return p
}

// periodicEmit 定时批处理累积的消息
func (p *batchingEmitterImpl) periodicEmit() {
	for !p.toDie() {
		time.Sleep(p.delay)
		p.lock.Lock()
		p.emit()
		p.lock.Unlock()
	}
}

func (p *batchingEmitterImpl) emit() {
	if p.toDie() {
		return
	}
	if len(p.buff) == 0 {
		return
	}
	msgs2beEmitted := make([]interface{}, len(p.buff))
	for i, v := range p.buff {
		msgs2beEmitted[i] = v.data
	}

	p.cb(msgs2beEmitted)
	p.decrementCounters()
}

func (p *batchingEmitterImpl) decrementCounters() {
	n := len(p.buff)
	for i := 0; i < n; i++ {
		msg := p.buff[i]
		msg.iterationsLeft--
		if msg.iterationsLeft == 0 {
			p.buff = append(p.buff[:i], p.buff[i+1:]...)
			n--
			i--
		}
	}
}

func (p *batchingEmitterImpl) toDie() bool {
	return atomic.LoadInt32(&(p.stopFlag)) == int32(1)
}

type batchingEmitterImpl struct {
	iterations int               // 消息转发的次数
	burstSize  int               // 触发转发的阈值
	delay      time.Duration     // 定时触发转发的时间
	cb         emitBatchCallback // 进行转发而调用的回调
	lock       *sync.Mutex
	buff       []*batchedMessage // 批处理消息
	stopFlag   int32
}

type batchedMessage struct {
	data           interface{}
	iterationsLeft int // 消息转发的剩余次数
}

func (p *batchingEmitterImpl) Stop() {
	atomic.StoreInt32(&(p.stopFlag), int32(1))
}

func (p *batchingEmitterImpl) Size() int {
	p.lock.Lock()
	defer p.lock.Unlock()
	return len(p.buff)
}

func (p *batchingEmitterImpl) Add(message interface{}) {
	if p.iterations == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()

	p.buff = append(p.buff, &batchedMessage{data: message, iterationsLeft: p.iterations})

	if len(p.buff) >= p.burstSize {
		// 达到触发转发的阈值，直接转发
		p.emit()
	}
}
