/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package common

import (
	"errors"

	"OntologyWithPOC/common"
	"OntologyWithPOC/common/log"
	"OntologyWithPOC/vm/neovm/types"
)

// ConvertReturnTypes return neovm stack element value
// According item types convert to hex string value
// Now neovm support type contain: ByteArray/Integer/Boolean/Array/Struct/Interop/StackItems
const (
	MAX_COUNT         = 1024
	MAX_NOTIFY_LENGTH = 64 * 1024 //64kb
)

func ConvertNeoVmTypeHexString(item interface{}) (interface{}, error) {
	var count int
	var length int
	res, err := convertNeoVmTypeHexString(item, &count, &length)
	if err != nil {
		return nil, err
	}
	if length > MAX_NOTIFY_LENGTH {
		return nil, errors.New("length over max parameters convert length")
	}
	return res, nil
}

func convertNeoVmTypeHexString(item interface{}, count *int, length *int) (interface{}, error) {
	if item == nil {
		return nil, nil
	}
	if *count > MAX_COUNT {
		return nil, errors.New("over max parameters convert length")
	}
	if *length > MAX_NOTIFY_LENGTH {
		return nil, errors.New("length over max parameters convert length")
	}
	switch v := item.(type) {
	case *types.ByteArray:
		arr, _ := v.GetByteArray()
		*length += len(arr)
		return common.ToHexString(arr), nil
	case *types.Integer:
		i, _ := v.GetBigInteger()
		if i.Sign() == 0 {
			*length += 1
			return common.ToHexString([]byte{0}), nil
		} else {
			bs := common.BigIntToNeoBytes(i)
			*length += len(bs)
			return common.ToHexString(bs), nil
		}
	case *types.Boolean:
		b, _ := v.GetBoolean()
		*length += 1
		if b {
			return common.ToHexString([]byte{1}), nil
		} else {
			return common.ToHexString([]byte{0}), nil
		}
	case *types.Array:
		var arr []interface{}
		ar, _ := v.GetArray()
		for _, val := range ar {
			*count++
			cv, err := convertNeoVmTypeHexString(val, count, length)
			if err != nil {
				return nil, err
			}
			arr = append(arr, cv)
		}
		return arr, nil
	case *types.Struct:
		var arr []interface{}
		ar, _ := v.GetStruct()
		for _, val := range ar {
			*count++
			cv, err := convertNeoVmTypeHexString(val, count, length)
			if err != nil {
				return nil, err
			}
			arr = append(arr, cv)
		}
		return arr, nil
	case *types.Interop:
		it, _ := v.GetInterface()
		*length += len(it.ToArray())
		return common.ToHexString(it.ToArray()), nil
	default:
		log.Error("[ConvertTypes] Invalid Types!")
		return nil, errors.New("[ConvertTypes] Invalid Types!")
	}
}
