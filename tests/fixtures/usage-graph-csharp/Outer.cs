namespace Example
{
    public class Outer
    {
        public class Inner
        {
            public int Compute()
            {
                // Unqualified call must attribute to the enclosing nested class.
                return Helper();
            }

            public int Helper()
            {
                return 1;
            }
        }
    }
}
