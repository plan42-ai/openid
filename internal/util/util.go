package util

func Coalesce[T comparable](values ...T) T {
	var zero T
	for _, v := range values {
		if v != zero {
			return v
		}
	}
	return zero
}

func Pointer[T any](v T) *T {
	return &v
}

func Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
