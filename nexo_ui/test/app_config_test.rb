# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require 'rbconfig'

class AppConfigTest < Minitest::Test
  REPO_ROOT = File.expand_path('../..', __dir__)

  def test_ui_bind_and_port_can_be_overridden_by_env
    script = <<~'RUBY'
      ENV['NEXO_UI_BIND'] = '127.0.0.1'
      ENV['NEXO_UI_PORT'] = '6789'
      require File.expand_path('nexo_ui/app.rb', Dir.pwd)
      puts Sinatra::Application.settings.bind
      puts Sinatra::Application.settings.port
    RUBY

    output, status = Open3.capture2e(RbConfig.ruby, '-e', script, chdir: REPO_ROOT)

    assert status.success?, output

    lines = output.lines.map(&:strip)
    assert_equal('127.0.0.1', lines[0])
    assert_equal('6789', lines[1])
  end
end
