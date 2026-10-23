package boundary15;
public class Fixture { public static class Base { public static class X {} } public static class Leaf extends Base {} public static class Use extends Unindexed { public Object value = Leaf.X; } }
