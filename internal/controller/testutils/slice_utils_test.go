/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testutils

import (
	"testing"
)

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{"item exists", []string{"a", "b", "c"}, "b", true},
		{"item not exists", []string{"a", "b", "c"}, "d", false},
		{"empty slice", []string{}, "a", false},
		{"nil slice", nil, "a", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Contains(tt.slice, tt.item)
			if result != tt.expected {
				t.Errorf("Contains(%v, %q) = %v, want %v", tt.slice, tt.item, result, tt.expected)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected []string
	}{
		{"remove existing item", []string{"a", "b", "c"}, "b", []string{"a", "c"}},
		{"remove non-existing item", []string{"a", "b", "c"}, "d", []string{"a", "b", "c"}},
		{"remove from empty slice", []string{}, "a", []string{}},
		{"remove multiple occurrences", []string{"a", "b", "b", "c"}, "b", []string{"a", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Remove(tt.slice, tt.item)
			if len(result) != len(tt.expected) {
				t.Errorf("Remove(%v, %q) length = %d, want %d", tt.slice, tt.item, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if i >= len(tt.expected) || v != tt.expected[i] {
					t.Errorf("Remove(%v, %q) = %v, want %v", tt.slice, tt.item, result, tt.expected)
					break
				}
			}
		})
	}
}
