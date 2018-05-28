package cortex

import (
	"context"
	"io"
	"sync"
	"time"
)

// MultiRun represents configuration for running multiple analyzers
type MultiRun struct {
	aso      *AnalyzerServiceOp
	Timeout  time.Duration
	ctx      context.Context
	OnReport func(*Report)
	OnError  func(error)
}

// NewMultiRun is a function that bootstraps MultiRun struct
func (a *AnalyzerServiceOp) NewMultiRun(ctx context.Context, d time.Duration) *MultiRun {
	return &MultiRun{
		aso:     a,
		Timeout: d,
		ctx:     ctx,
	}
}

// Do analyzes an observable with all appropriate analyzers
func (m *MultiRun) Do(o Observable) error {
	ans, _, err := m.aso.ListByType(m.ctx, o.Type())
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(len(ans))
	defer wg.Wait()

	switch o.(type) {
	case *FileTask:
		err := m.AnalyzeFile(&wg, o.(*FileTask), ans...)
		if err != nil {
			return err
		}
	case *Task:
		err := m.AnalyzeString(&wg, o.(*Task), ans...)
		if err != nil {
			return err
		}
	}

	return nil
}

// AnalyzeFile analyses a file observable by multiple analyzers
func (m *MultiRun) AnalyzeFile(wg *sync.WaitGroup, ft *FileTask, ans ...Analyzer) error {
	var (
		readPipes  []*io.PipeReader
		writePipes []*io.PipeWriter
	)

	for i := range ans {
		fr, fw := io.Pipe()
		readPipes = append(readPipes, fr)
		writePipes = append(writePipes, fw)

		o := &FileTask{
			FileName:     ft.FileName,
			Reader:       fr,
			FileTaskMeta: ft.FileTaskMeta,
		}

		go func(an Analyzer, f io.Reader) error {
			defer wg.Done()

			report, err := m.aso.run(m.ctx, an.ID, o, m.Timeout)
			if err != nil && m.OnError != nil {
				m.OnError(err)
			}
			if err == nil && report != nil && m.OnReport != nil {
				m.OnReport(report)
			}

			return nil
		}(ans[i], fr)
	}

	wr := make([]io.Writer, len(writePipes))
	for i := range writePipes {
		wr[i] = writePipes[i]
	}

	mw := io.MultiWriter(wr...)
	go func() error {
		if _, err := io.Copy(mw, ft.Reader); err != nil {
			return err
		}
		for i := range writePipes {
			writePipes[i].Close()
		}
		return nil
	}()

	return nil
}

// AnalyzeString analyses a basic string-alike observable by multiple analyzers
func (m *MultiRun) AnalyzeString(wg *sync.WaitGroup, t *Task, ans ...Analyzer) error {
	for i := range ans {
		go func(an Analyzer) error {
			defer wg.Done()

			report, err := m.aso.run(m.ctx, an.ID, t, m.Timeout)
			if err != nil && m.OnError != nil {
				m.OnError(err)
			}
			if err == nil && report != nil && m.OnReport != nil {
				m.OnReport(report)
			}

			return nil
		}(ans[i])
	}

	return nil
}
