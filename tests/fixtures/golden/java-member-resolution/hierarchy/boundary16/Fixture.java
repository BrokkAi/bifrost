package boundary16;
public class Fixture { public static class Base { public int x; public int m() { return 1; } } public static class Leaf extends Base {} public static class Use extends Unindexed { public int field(Leaf v) { return v.x; } public int call(Leaf v) { return v.m(); } } }
