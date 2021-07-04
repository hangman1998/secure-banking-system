package dto;

import java.util.HashMap;
import java.util.Map;

public enum IntLevel
{
    VeryTrusted("vt", 3),
    Trusted("t", 2),
    SlightlyTrusted("st", 1),
    Untrusted("ut", 0);
    public final String label;
    public final int level;
    private static final Map<String, IntLevel> BY_LABEL = new HashMap<>();

    static {
        for (IntLevel e : values()) {
            BY_LABEL.put(e.label, e);
        }
    }
    private IntLevel(String label, int level) {
        this.label = label;
        this.level = level;
    }
    public static IntLevel valueOfLabel(String label) {
        return BY_LABEL.get(label);
    }

}