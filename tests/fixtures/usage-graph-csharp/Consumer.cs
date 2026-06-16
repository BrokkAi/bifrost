namespace Example
{
    public class Consumer
    {
        public int ViaInstance()
        {
            Service s = new Service();
            return s.Run();
        }

        public int ViaStatic()
        {
            return Service.Helper();
        }

        public Service MakeService()
        {
            return new Service();
        }

        public int Shadowed(Service Run)
        {
            // `Run` is a Service-typed parameter; `Run.Run()` resolves to
            // Service.Run via the receiver type, not the member name alone.
            return Run.Run();
        }

        public int WrongReceiver(Consumer other)
        {
            // `other` is a Consumer with no `Run()`; resolves to Consumer.Run
            // (not a node), so this must NOT edge to Service.Run.
            return other.Run();
        }

        public int Local()
        {
            return 7;
        }

        public int CallsLocal()
        {
            // Unqualified call attributes to the enclosing class.
            return Local();
        }
    }
}
