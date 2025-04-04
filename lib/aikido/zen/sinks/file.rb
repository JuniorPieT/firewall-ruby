# frozen_string_literal: true

module Aikido::Zen
  module Sinks
    module File
        SINK = Sinks.add("file", scanners: [Aikido::Zen::Scanners::PathTraversal::PathTraversalScanner])

      module Extensions
        def read(path, *args)
            puts "[Zen] Intercepted File.read with path: #{path}"
            context = Aikido::Zen.current_context
            SINK.scan(
                path: path,
                operation: "read",
                request: context && context["ssrf.request"]
            )
            super
        end

      end
    end
  end
end

::File.singleton_class.prepend(Aikido::Zen::Sinks::File::Extensions)
