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

func TestGenerateRandomPassword(t *testing.T) {
	p1, err := GenerateRandomPassword(24)
	if err != nil {
		t.Fatalf("GenerateRandomPassword: %v", err)
	}
	p2, err := GenerateRandomPassword(24)
	if err != nil {
		t.Fatalf("GenerateRandomPassword: %v", err)
	}
	if p1 == p2 {
		t.Fatal("two consecutive random passwords were equal")
	}
	if len(p1) < 24 {
		t.Fatalf("password too short: %d", len(p1))
	}
}

func TestGenerateRandomPasswordTooFewBytes(t *testing.T) {
	if _, err := GenerateRandomPassword(8); err == nil {
		t.Fatal("GenerateRandomPassword(8) returned nil error")
	}
}
