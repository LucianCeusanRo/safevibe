from safevibe.romanian import cnp_control_digit, cui_control_digit, is_valid_cnp, is_valid_cui

SYNTHETIC_CNP = "1900115100015"
SYNTHETIC_CUI = "123456789"


def test_synthetic_cnp_checksum_is_valid():
    assert is_valid_cnp(SYNTHETIC_CNP)
    assert cnp_control_digit(SYNTHETIC_CNP[:12]) == SYNTHETIC_CNP[12]


def test_invalid_cnp_checksum_rejected():
    assert not is_valid_cnp("1900115100010")


def test_impossible_cnp_date_rejected():
    # 31 February, checksum whatever
    assert not is_valid_cnp("1900231123456")


def test_synthetic_cui_checksum_is_valid():
    assert is_valid_cui(SYNTHETIC_CUI)
    assert is_valid_cui("RO123456789")
    assert cui_control_digit("12345678") == "9"


def test_invalid_cui_rejected():
    assert not is_valid_cui("123456780")
    assert not is_valid_cui("1")
