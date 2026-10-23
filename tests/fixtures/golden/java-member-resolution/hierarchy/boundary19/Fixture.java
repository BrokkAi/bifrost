package boundary19;
public class Fixture { public static class Far { public int x; } public static class Near extends Far { public int x; } public static class Leaf extends Near {} public static class Use extends Unindexed { public int fromLeaf(Leaf v) { return v.x; } public int fromNear(Near v) { return v.x; } } }
