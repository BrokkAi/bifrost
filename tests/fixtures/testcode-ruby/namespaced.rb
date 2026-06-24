module Alpha
  module Beta
    class Gamma
      GREETING = "hi"

      def hello
        GREETING
      end

      def self.build
        new
      end
    end
  end
end
