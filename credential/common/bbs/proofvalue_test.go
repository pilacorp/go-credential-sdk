package bbs

import "testing"

func TestParseBaseProofValue_W3CVector(t *testing.T) {
	proofValue := "u2V0ChVhQhhaN0rXQx8alajD0IS7RFqU97wXQ1nCCB9SDx_8gU676ItJLp2WdYIUmlPjYW-D6Ktw5dMfcTMaLPbF7JCOXUEcQQWLCRQK0FZGHmsJPG7FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfjnzCLDGN0glOAtC_BsXXOl26cXYRpA9tG-3F6nwwD9ZYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-BZy9pc3N1ZXI"
	got, err := parseBaseProofValue(proofValue)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BBSSignature) == 0 || len(got.BBSHeader) == 0 || len(got.PublicKey) == 0 || len(got.HMACKey) == 0 {
		t.Fatalf("expected non-empty parsed fields")
	}
	if len(got.MandatoryPointers) != 1 || got.MandatoryPointers[0] != "/issuer" {
		t.Fatalf("unexpected mandatory pointers: %#v", got.MandatoryPointers)
	}
}

func TestParseDerivedProofValue_W3CVector(t *testing.T) {
	proofValue := "u2V0DhVkC0JasX_e4m_LYsPPMUcVH8aIrAeJOJGV50hI2LN9r8Pq-GL4MnR-EyQS7TGxhP9Dsq7etkuYVNB2pekWpGHIWJsyFnEVbRzo245VyVh1fxIPGN0JHF6Q9z_s7Ew2P4R-IqIAvOyMe_iRE-LR_7e0LYh49XNIss-wj68T23KdFtcHOL0KnELklEKcSJafTngDgwm2i-uJCzfFU6T3kIBcnC5kCP-lbQsQqRhouqxngSqRIOa85qnH4MBYstCSlqgrMBG3H57i9_HPPNkHHau63-7Vs2TZ3YFDb1jK_f8gNM8Yh3GuDcYSt5hljD3K9Jdiupia6mU0Vpl3vGw3IrwnFSgz15bVNGxsoBHqi2_Y4Bf7JUzurRtEjScpH39g_8wRUztrNI9pOuaPr4ZjICsGZLiogP_z0avqjSCpjt7AAM98aLaNh1gChz9UTm-AQyjAuCCr37jSl_z0kzHBi9X-jbUeEbt1SGeWb1DhXa_9wm_15INa62DZ7D-jHSTGO-HJr7anB2Qlb7XOOT9HDgzOif08gcaIahjZxtD_lIfc3REvoZeiHy_M8qjkib7gBMANyHjfG2UmGe--6HIt79kG9ZHhRrZKu09qRr1LxfQWKn3TrMHRDBMBYE4QL5qUo9UzVoktzri9C3sG_wuE1T7BhqWwN86uW3cmtqWy4glcczLiXdPzwMm4ciyuHzEz06vvXVjJRiRnL5Yqfhq3hKw9picCIbjWNgBuZsd0yx-blamU8DiZKhLUdLSNnnHXigkUa87yqbxnse8OqYD_sh9taV9QpYeKQfYmaj9XRzhfd6Kdc0RkklM2TsRLad3TCuy9nn1tLQE2r5IXXigF7K-geX_i6z5DV8ksug6tBafj1XKb3AxQfkVZau-x0RebPRmP140uRiCg9V87fNsWGsYoTC4NlJDa_aGJnPd7r2a79wvv8l93oDjZINJHENXzNL8Ex-6IAAAEChAAEBQeGAAEHERITRBEzd6o"
	got, err := parseDerivedProofValue(proofValue)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.bbsProof) == 0 {
		t.Fatalf("expected bbsProof")
	}
	if len(got.mandatoryIndexes) == 0 || len(got.selectiveIndexes) == 0 {
		t.Fatalf("expected indexes")
	}
	if len(got.presentationHeader) == 0 {
		t.Fatalf("expected presentation header")
	}
}
