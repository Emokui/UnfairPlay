package progress

import "context"

type key struct{}

func WithContext(ctx context.Context, report func(string)) context.Context {
	return context.WithValue(ctx, key{}, report)
}
func Report(ctx context.Context, message string) {
	if report, ok := ctx.Value(key{}).(func(string)); ok && report != nil {
		report(message)
	}
}
