package util

import "reflect"

// ComposeHooks modifies func fields t to call the corresponding ones in next
// afterwards, if defined.
//
// inspired by net/http/httptrace
func ComposeHooks(t, next any) {
	tv := reflect.ValueOf(t).Elem()
	ov := reflect.ValueOf(next).Elem()
	structType := tv.Type()
	for i := 0; i < structType.NumField(); i++ {
		tf := tv.Field(i)
		hookType := tf.Type()
		if hookType.Kind() != reflect.Func {
			continue
		}
		of := ov.Field(i)
		if of.IsNil() {
			continue
		}
		if tf.IsNil() {
			tf.Set(of)
			continue
		}
		tfCopy := reflect.ValueOf(tf.Interface())
		newFunc := reflect.MakeFunc(hookType, func(args []reflect.Value) []reflect.Value {
			tfCopy.Call(args)
			return of.Call(args)
		})
		tv.Field(i).Set(newFunc)
	}
}
