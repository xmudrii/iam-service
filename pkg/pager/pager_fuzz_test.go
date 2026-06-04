package pager

import (
	"testing"

	"github.com/platform-mesh/iam-service/pkg/graph"
)

// maxFuzzSliceLen bounds the synthesized slice size so the fuzzer explores
// pagination arithmetic without allocating unbounded memory.
const maxFuzzSliceLen = 2048

// FuzzPaginateUsers fuzzes the pagination bounds arithmetic. limit and page
// originate from the GraphQL PageInput and are fully client-controlled, so
// adversarial values must never make the slicing panic (e.g. via integer
// overflow producing a negative offset). The fuzzer drives the function with
// arbitrary limit/page values against a realistically-sized backing slice and
// asserts the documented invariants hold.
func FuzzPaginateUsers(f *testing.F) {
	// page, limit, sliceLen, useDefaults (page/limit nil when true)
	f.Add(1, 10, 25, false)
	f.Add(3, 5, 25, false)
	f.Add(0, 0, 0, false)
	f.Add(-1, -1, 10, false)
	f.Add(1, 10, 0, true)
	// Overflow-prone values: (page-1)*limit wraps around int.
	f.Add(1<<31, 1<<31, 100, false)
	f.Add(2147483647, 2147483647, 50, false)
	f.Add(-2147483648, 2, 50, false)
	// Regression: (page-1)*limit == 2^63 wraps to a negative offset and used
	// to panic with a negative slice bound.
	f.Add((1<<62)+1, 2, 50, false)

	pager := NewDefaultPager()

	f.Fuzz(func(t *testing.T, page, limit, sliceLen int, useDefaults bool) {
		// Clamp the backing slice to a sane, non-negative size.
		if sliceLen < 0 {
			sliceLen = -sliceLen
		}
		sliceLen %= maxFuzzSliceLen + 1

		users := make([]*graph.User, sliceLen)
		for i := range users {
			users[i] = &graph.User{}
		}

		var pageInput *graph.PageInput
		if !useDefaults {
			p, l := page, limit
			pageInput = &graph.PageInput{Page: &p, Limit: &l}
		}

		// Must not panic for any client-supplied page/limit.
		result, info := pager.PaginateUsers(users, pageInput, len(users))

		if info == nil {
			t.Fatalf("nil PageInfo returned")
		}
		if info.Count != len(result) {
			t.Fatalf("PageInfo.Count=%d but returned %d users", info.Count, len(result))
		}
		if info.TotalCount != len(users) {
			t.Fatalf("PageInfo.TotalCount=%d but slice len=%d", info.TotalCount, len(users))
		}
		if len(result) > len(users) {
			t.Fatalf("returned more users (%d) than exist (%d)", len(result), len(users))
		}
	})
}
