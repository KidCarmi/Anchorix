package auth

import "testing"

func TestPasswordPolicyHashAndVerify(t *testing.T) {
	p, err := NewPasswordPolicy(10) // 10 = cheapest acceptable; keeps the test fast
	if err != nil {
		t.Fatalf("NewPasswordPolicy: %v", err)
	}
	hash, err := p.Hash("hunter2-and-then-some")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := p.Verify(hash, "hunter2-and-then-some"); err != nil {
		t.Fatalf("Verify (correct password): %v", err)
	}
	if err := p.Verify(hash, "wrong-password"); err == nil {
		t.Fatal("Verify (wrong password) returned nil")
	}
}

func TestPasswordPolicyRejectsEmptyPassword(t *testing.T) {
	p, err := NewPasswordPolicy(10)
	if err != nil {
		t.Fatalf("NewPasswordPolicy: %v", err)
	}
	if _, err := p.Hash(""); err == nil {
		t.Fatal("Hash(empty) returned nil")
	}
}

func TestPasswordPolicyCostBounds(t *testing.T) {
	for _, c := range []int{9, 15, 0, -1, 100} {
		if _, err := NewPasswordPolicy(c); err == nil {
			t.Fatalf("NewPasswordPolicy(%d) returned no error", c)
		}
	}
	for _, c := range []int{10, 12, 14} {
		if _, err := NewPasswordPolicy(c); err != nil {
			t.Fatalf("NewPasswordPolicy(%d): %v", c, err)
		}
	}
}
