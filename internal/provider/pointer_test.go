package provider_test

func P[T any](v T) *T { return &v }
