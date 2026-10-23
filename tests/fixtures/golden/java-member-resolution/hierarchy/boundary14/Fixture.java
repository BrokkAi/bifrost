package boundary14;
public class Fixture { public static class A extends B {} public static class B extends A { public int x; } public static class Use extends Unindexed { public int inherited(A v) { return v.x; } public int direct(B v) { return v.x; } } }
