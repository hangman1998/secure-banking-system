package dto;

import java.util.HashMap;
import java.util.Map;

public enum AccountType
{
    SHORT_TERM_SAVING_ACCOUNT("st"),
    LONG_TERM_SAVING_ACCOUNT("lt"),
    CURRENT_ACCOUNT("c"),
    INTEREST_FREE_DEPOSIT_ACCOUNT("d");
    public final String label;
    private static final Map<String, AccountType> BY_LABEL = new HashMap<>();

    static {
        for (AccountType e : values()) {
            BY_LABEL.put(e.label, e);
        }
    }
    private AccountType(String label) {
        this.label = label;
    }
    public static AccountType valueOfLabel(String label) {
        return BY_LABEL.get(label);
    }
}