require "test_helper"

class Aikido::Zen::Scanners::PathTraversalTest < ActiveSupport::TestCase
    def setup
        @scanner = Aikido::Zen::Scanners::PathTraversal::PathTraversalScanner
    end

  def test_empty_user_input
    assert_equal false, @scanner.vulnerable_path?("test.txt", "")
  end

  def test_empty_file_input
    assert_equal false, @scanner.vulnerable_path?("", "test")
  end

  def test_empty_both_inputs
    assert_equal false, @scanner.vulnerable_path?("", "")
  end

  def test_user_input_single_character
    assert_equal false, @scanner.vulnerable_path?("test.txt", "t")
  end

  def test_file_input_single_character
    assert_equal false, @scanner.vulnerable_path?("t", "test")
  end

  def test_same_as_user_input
    assert_equal false, @scanner.vulnerable_path?("text.txt", "text.txt")
  end

  def test_directory_before
    assert_equal false, @scanner.vulnerable_path?("directory/text.txt", "text.txt")
  end

  def test_directory_and_file_same
    assert_equal false, @scanner.vulnerable_path?("directory/text.txt", "directory/text.txt")
  end

  def test_both_single_character
    assert_equal false, @scanner.vulnerable_path?("t", "t")
  end

  def test_detect_basic_traversal
    assert_equal true, @scanner.vulnerable_path?("../test.txt", "../")
    assert_equal true, @scanner.vulnerable_path?("..\\test.txt", "..\\")
    assert_equal true, @scanner.vulnerable_path?("../../test.txt", "../../")
    assert_equal true, @scanner.vulnerable_path?("..\\..\\test.txt", "..\\..\\")
    assert_equal true, @scanner.vulnerable_path?("../../../../test.txt", "../../../../")
    assert_equal true, @scanner.vulnerable_path?("..\\..\\..\\test.txt", "..\\..\\..\\")
    assert_equal true, @scanner.vulnerable_path?("./../test.txt", "./../")
  end

  def test_user_input_longer_than_file
    assert_equal false, @scanner.vulnerable_path?("../file.txt", "../../file.txt")
  end

  def test_absolute_linux_path
    assert_equal true, @scanner.vulnerable_path?("/etc/passwd", "/etc/passwd")
  end

  def test_linux_user_directory
    assert_equal true, @scanner.vulnerable_path?("/home/user/file.txt", "/home/user/")
  end

  def test_possible_bypass
    assert_equal true, @scanner.vulnerable_path?("/./etc/passwd", "/./etc/passwd")
  end

  def test_another_bypass
    assert_equal true, @scanner.vulnerable_path?("/./././root/test.txt", "/./././root/test.txt")
    assert_equal true, @scanner.vulnerable_path?("/./././root/test.txt", "/./././root")
  end

  def test_no_path_traversal
    assert_equal false, @scanner.vulnerable_path?("/appdata/storage/file.txt", "/storage/file.txt")
    assert_equal false, @scanner.vulnerable_path?("/app/test.txt", "test")
    assert_equal false, @scanner.vulnerable_path?("/app/data/example/test.txt", "example/test.txt")
    assert_equal false, @scanner.vulnerable_path?("/etc/app/config", "/etc/hack/config")
    assert_equal false, @scanner.vulnerable_path?("/etc/app/data/etc/config", "/etc/config")
  end

  def test_disable_check_path_start
    assert_equal false, @scanner.vulnerable_path?("/etc/passwd", "/etc/passwd", check_path_start: false)
  end

  def test_no_filename_in_user_input
    assert_equal false, @scanner.vulnerable_path?("/etc/app/test.txt", "/etc/")
    assert_equal false, @scanner.vulnerable_path?("/etc/app/", "/etc/")
    assert_equal false, @scanner.vulnerable_path?("/etc/app/", "/etc")
    assert_equal false, @scanner.vulnerable_path?("/etc/", "/etc/")
    assert_equal false, @scanner.vulnerable_path?("/etc", "/etc")
    assert_equal false, @scanner.vulnerable_path?("/var/a", "/var/")
    assert_equal false, @scanner.vulnerable_path?("/var/a", "/var/b")
    assert_equal false, @scanner.vulnerable_path?("/var/a", "/var/b/test.txt")
  end

  def test_user_input_contains_filename_or_subfolder
    assert_equal true, @scanner.vulnerable_path?("/etc/app/file.txt", "/etc/app")
    assert_equal true, @scanner.vulnerable_path?("/etc/app/file.txt", "/etc/app/file.txt")
    assert_equal true, @scanner.vulnerable_path?("/var/backups/file.txt", "/var/backups")
    assert_equal true, @scanner.vulnerable_path?("/var/backups/file.txt", "/var/backups/file.txt")
    assert_equal true, @scanner.vulnerable_path?("/var/a", "/var/a")
    assert_equal true, @scanner.vulnerable_path?("/var/a/b", "/var/a")
    assert_equal true, @scanner.vulnerable_path?("/var/a/b/test.txt", "/var/a")
  end
end
