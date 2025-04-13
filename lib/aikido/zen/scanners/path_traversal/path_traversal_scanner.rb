# frozen_string_literal: true

require_relative "../../attack"

module Aikido::Zen
  module Scanners
    module PathTraversal
      class PathTraversalScanner
        DANGEROUS_PATH_PARTS = ["../", "..\\"].freeze

        DANGEROUS_PATH_STARTS = [
          "/bin/",
          "/boot/",
          "/dev/",
          "/etc/",
          "/home/",
          "/init/",
          "/lib/",
          "/media/",
          "/mnt/",
          "/opt/",
          "/proc/",
          "/root/",
          "/run/",
          "/sbin/",
          "/srv/",
          "/sys/",
          "/tmp/",
          "/usr/",
          "/var/",
          "c:/",
          "c:\\"
        ].freeze

        def self.call(sink:, context:, path:, operation:, **_kwargs)
          # Ignore if there is no context (non-user initiated action)
          return unless context
         
          # Ignore if no user input caputed in context
          user_input = context['path_traversal.input']
          return unless user_input

          if vulnerable_path?(path, user_input)
            return Attacks::PathTraversalAttack.new(
              sink: sink,
              context: context,
              operation: operation,
              path: path,
              input: user_input
            )
          end
        end

        def self.vulnerable_path?(file_path, user_input, check_path_start: true, is_url: false)
          # Ignore single characters
          return false if user_input.length <= 1

          # Ignore if user_input is longer than file_path
          return false if user_input.length > file_path.length

          # Ignore if user_input is not part of file_path
          return false unless file_path.include?(user_input)

          if contains_unsafe_path_parts?(file_path) && contains_unsafe_path_parts?(user_input)
            return true
          end

          if check_path_start
            return starts_with_unsafe_path?(file_path, user_input)
          end

          false
        end

        def self.contains_unsafe_path_parts?(path)
          DANGEROUS_PATH_PARTS.any? { |dangerous_part| path.include?(dangerous_part) }
        end

        def self.starts_with_unsafe_path?(file_path, user_input)
          return false unless absolute_path?(file_path) && absolute_path?(user_input)

          normalized_file_path = File.expand_path(file_path).downcase
          normalized_user_input = File.expand_path(user_input).downcase

          DANGEROUS_PATH_STARTS.any? do |dangerous_start|
            normalized_file_path.start_with?(dangerous_start) &&
              normalized_file_path.start_with?(normalized_user_input) &&
              user_input != dangerous_start &&
              user_input != dangerous_start.chomp("/")
          end
        end

        def self.absolute_path?(path)
          Pathname.new(path).absolute?
        end

        def self.parse_as_file_url(path)
          url = path.dup
          unless url.start_with?("file:")
            url = "file:///" + url unless url.start_with?("/")
            url = "file://" + url unless url.start_with?("file://")
          end

          begin
            uri = URI.parse(url)
            return uri.path if uri.scheme == "file"
          rescue URI::InvalidURIError
            nil
          end

          nil
        end
      end
    end
  end
end
