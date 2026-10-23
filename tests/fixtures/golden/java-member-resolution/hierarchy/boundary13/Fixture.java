package boundary13;
public class Fixture { public interface A extends C {} public interface C extends A {} public interface Mid extends A {} public interface Good { int x = 1; } public static class Leaf implements Mid, Good {} public static class Use extends Unindexed { public int f(Leaf v) { return v.x; } } }
