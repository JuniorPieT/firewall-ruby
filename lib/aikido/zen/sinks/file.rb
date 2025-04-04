# frozen_string_literal: true

module Aikido::Zen
  module Sinks
    module File
        SINK = Sinks.add("file", scanners: [Aikido::Zen::Scanners::PathTraversal::PathTraversalScanner])

      module Extensions
        def read(path, *args)
            SINK.scan(
                path: path,
                operation: "read"
            )
            super
        end

      end
    end
  end
end

::File.singleton_class.prepend(Aikido::Zen::Sinks::File::Extensions)
