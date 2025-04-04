# frozen_string_literal: true

require "thread"

module HTTPX
  class SynchPool < Pool
    def initialize(options)
      super

      @connections = ConnectionStore.new(options)
    end

    # TODO: #wrap
    def find_or_new_connection(uri, options, &blk)
      @connections.find_or_new(uri, options) do |new_conn|
        catch(:coalesced) do
          init_connection(new_conn, options)
          blk.call(new_conn) if blk
          new_conn
        end
      end
      find_connection(uri, options) || new_connection(uri, options, &blk)
    end

    class ConnectionManager
      include Enumerable

      def initialize(limit = 3)
        @connections = []
        @used = 0
        @limit = limit
      end

      def each(*args, &blk)
        @connections.each(*args, &blk)
      end

      def find_or_new(uri, options, &blk)
        raise "over limit" if @used >= @limit

        @used += 1
        conn = @connections.find do |connection|
          connection.match?(uri, options)
        end

        if conn
          @connections.delete(conn)
        else
          conn = options.connection_class.new(uri, options)
          blk[conn]
        end

        conn
      end
    end

    class ConnectionStore
      include Enumerable

      def initialize(options)
        @connections = Hash.new { |hs, k| hs[k] ||= ConnectionManager.new }
        @conn_mtx = Thread::Mutex.new
        @conn_waiter = ConditionVariable.new
        @timeout = Float(options.fetch(:pool_timeout, 5))
      end

      def each(&block)
        return enum_for(__meth__) unless block

        @conn_mtx.synchronize do
          @connections.each_value do |conns|
            conns.each(&block)
          end
        end
      end

      def find_or_new(uri, options, &blk)
        @connections[uri.origin].find_or_new(uri, options, &blk)
      end

      # def <<(conn)
      #   @conn_mtx.synchronize do
      #     origin, conns = @connections.find { |_orig, _| conn.origins.include?(origin) }
      #     (conns || @connections[conn.origin.to_s]) << conn
      #   end
      # end

      def empty?
        @conn_mtx.synchronize { super }
      end
    end
  end
end
