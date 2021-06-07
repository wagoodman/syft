package task

import (
	"fmt"
	"sync"

	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/source"
	"github.com/hashicorp/go-multierror"
)

func Execute(appConfig config.Application, src source.Source, products ...Product) (Result, error) {
	tasks, err := createTasks(appConfig, products...)
	if err != nil {
		return Result{}, err
	}

	analysisResults := Result{
		SourceMetadata:    src.Metadata,
		ApplicationConfig: appConfig,
	}

	var taskErr error
	wg := &sync.WaitGroup{}
	for _, task := range tasks {
		wg.Add(1)
		go func(task Task) {
			defer wg.Done()
			if err = task(&analysisResults, src); err != nil {
				taskErr = multierror.Append(taskErr, err)
				return
			}
		}(task)
	}
	wg.Wait()

	if taskErr != nil {
		return Result{}, taskErr
	}

	return analysisResults, nil
}

func createTasks(appConfig config.Application, factories []Factory) ([]Task, error) {
	var tasks []Task
	for _, f := range factories {
		t, err := f(appConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to create task : %w", err)
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}
