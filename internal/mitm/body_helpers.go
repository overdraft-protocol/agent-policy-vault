package mitm

import (
	"bytes"
	"io"
	"net/http"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// materializeRequestBodyWithBytes mirrors brokercore.MaterializeRequestBody
// but additionally returns the raw byte slice so callers (the policy
// decision point) can inspect the body without re-reading it. The
// returned ReadCloser is a fresh reader over the same bytes so the
// outbound request can stream them upstream with a real Content-Length.
//
// Callers MUST wrap body in http.MaxBytesReader before invoking so a
// hostile client can't exhaust memory; size-cap violations surface as
// *http.MaxBytesError, identical to MaterializeRequestBody.
func materializeRequestBodyWithBytes(body io.ReadCloser) (io.ReadCloser, int64, []byte, error) {
	if body == nil || body == http.NoBody {
		return http.NoBody, 0, nil, nil
	}
	defer func() { _ = body.Close() }()

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(data) == 0 {
		return http.NoBody, 0, nil, nil
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), data, nil
}

// Compile-time assertion that brokercore is imported (silences linters
// in case future edits drop the only consumer of the package).
var _ = brokercore.MaxProxyBodyBytes
