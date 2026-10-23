package boundary4;
public class Generated { public static class BaseWorker {} public static class Module00000 extends BaseWorker { public int changed(int value) { return value; } } public int predecessor(Module00000 previous, int value) { return previous.changed(value); } }
