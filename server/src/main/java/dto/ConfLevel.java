package dto;

import java.util.HashMap;
import java.util.Map;

public enum ConfLevel
{
    TopSecret("ts", 3),
    Secret("s", 2),
    Confidential("c", 1),
    Unclassified("uc", 0);
    public final String label;
    public final int level;
    private static final Map<String, ConfLevel> BY_LABEL = new HashMap<>();

    static {
        for (ConfLevel e : values()) {
            BY_LABEL.put(e.label, e);
        }
    }
    private ConfLevel(String label, int level) {
        this.label = label;
        this.level = level;
    }
    public static ConfLevel valueOfLabel(String label) {
        return BY_LABEL.get(label);
    }
}