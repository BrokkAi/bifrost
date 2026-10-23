package boundary18;
public class Fixture { public interface Top { int x = 1; } public interface Left extends Top {} public interface Right extends Top {} public static class Leaf implements Left, Right {} public static class Use extends Unindexed { public int f(Leaf v) { return v.x; } } }
