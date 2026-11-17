package assets

import (
	"context"
	"github.com/majd/ipatool/v2/internal/progress"
)

func WithProgress(ctx context.Context, report func(string)) context.Context {
	return progress.WithContext(ctx, report)
}

func reportProgress(ctx context.Context, message string) {
	progress.Report(ctx, message)
}
