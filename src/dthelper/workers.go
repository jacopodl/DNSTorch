package dthelper

import (
	"sync"
	"time"
)

type BGFunc func(params ...interface{}) (interface{}, bool)
type FGFunc func(params interface{})

type Workers struct {
	doInBackground BGFunc
	progressUpdate FGFunc
	total          int
	cond           *sync.Cond
	delay          time.Duration
	outchan        chan interface{}
}

type BgResult struct {
	Data    interface{}
	IsError bool
}

func NewWorkers(delay time.Duration, bg BGFunc, fg FGFunc) *Workers {
	workers := &Workers{
		doInBackground: bg,
		progressUpdate: fg,
		cond:           sync.NewCond(&sync.Mutex{}),
		delay:          delay,
		outchan:        make(chan interface{}, 10)}
	return workers
}

func (w *Workers) Spawn(number int, params ...interface{}) {
	w.total = number + 1

	go w.fgWorker()

	for i := 0; i < number; i++ {
		go w.bgWorker(w.delay*time.Duration(number), params...)
		if w.delay > 0 {
			time.Sleep(w.delay)
		}
	}
}

func (w *Workers) Wait() {
	w.cond.L.Lock()
	for w.total > 1 {
		w.cond.Wait()
	}
	close(w.outchan)
	for w.total == 0 {
		w.cond.Wait()
	}
	w.cond.L.Unlock()
}

func (w *Workers) bgWorker(delay time.Duration, params ...interface{}) {
	defer w.decTotal()
	for {
		progress, exit := w.doInBackground(params...)
		if progress != nil {
			w.outchan <- progress
		}
		if exit {
			break
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}

func (w *Workers) fgWorker() {
	defer w.decTotal()
	for {
		if data, ok := <-w.outchan; !ok {
			break
		} else {
			w.progressUpdate(data)
		}
	}
}

func (w *Workers) decTotal() {
	w.cond.L.Lock()
	w.total--
	w.cond.Broadcast()
	w.cond.L.Unlock()
}
