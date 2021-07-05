package dto;

public enum FailReason {
    BAD_INPUT,
    DUP_USERNAME,
    WEAK_PASS,
    NON_EXISTENT_USERNAME,
    WRONG_PASS,
    BAN_USER,
    INVALID_ACCOUNT_NUM,
    DUPLICATE_JOIN_REQUEST,
    INVALID_INT_LEVEL,
    INVALID_CONF_LEVEL,
    INVALID_ACC_TYPE,
    NOT_OWNER,
    ALREADY_AN_OWNER,
    NON_EXISTENT_REQUEST,
    NEGATIVE_AMOUNT,
    NO_READ_RIGHT,
    NO_WRITE_RIGHT,
    INSUFFICIENT_FUNDS
}
