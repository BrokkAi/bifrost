package boundary17;
public class Fixture { public interface Left { int x = 1; } public interface Right { int x = 2; } public static class Leaf implements Left, Right {} public static class Use extends Unindexed { public int f(Leaf v) { return v.x; } } }
