// Copyright (C) 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jdwp

// GetTypeSignature returns the Java type signature for the specified type.
func (c *Connection) GetTypeSignature(ty ReferenceTypeID) (string, error) {
	return c.get[string](cmdReferenceTypeSignature, ty)
}

// GetFields returns all the fields for the specified type.
func (c *Connection) GetFields(ty ReferenceTypeID) (Fields, error) {
	return c.get[Fields](cmdReferenceTypeFields, ty)
}

// GetMethods returns all the methods for the specified type.
func (c *Connection) GetMethods(ty ReferenceTypeID) (Methods, error) {
	return c.get[Methods](cmdReferenceTypeMethods, ty)
}

// GetStaticFieldValues returns the values of all the requests static fields.
func (c *Connection) GetStaticFieldValues(ty ReferenceTypeID, fields ...FieldID) ([]Value, error) {
	return c.get[[]Value](cmdReferenceTypeGetValues, struct {
		Ty     ReferenceTypeID
		Fields []FieldID
	}{ty, fields})
}

// GetImplemented returns all the direct interfaces implemented by the specified
// type.
func (c *Connection) GetImplemented(ty ReferenceTypeID) ([]InterfaceID, error) {
	return c.get[[]InterfaceID](cmdReferenceTypeInterfaces, ty)
}
