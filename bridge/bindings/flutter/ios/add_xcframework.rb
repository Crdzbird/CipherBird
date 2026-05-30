#!/usr/bin/env ruby
# Register Frameworks/CryptoLib.xcframework with the Runner target so iOS
# app builds pick up the prebuilt static library and its public headers.
#
# Idempotent: re-running won't duplicate the reference.

require 'xcodeproj'
require 'pathname'

SCRIPT_DIR = Pathname(__FILE__).realpath.dirname
PROJ_PATH  = SCRIPT_DIR + 'Runner.xcodeproj'
XCFW_REL   = 'Frameworks/CryptoLib.xcframework'

project = Xcodeproj::Project.open(PROJ_PATH.to_s)
target  = project.targets.find { |t| t.name == 'Runner' } \
          or abort "Runner target not found"

# Locate or create the Frameworks group
fw_group = project.main_group['Frameworks'] || project.main_group.new_group('Frameworks')

# Add XCFramework as a file reference (skip if already present)
xcfw_ref = fw_group.files.find { |f| f.path == XCFW_REL } \
        || fw_group.new_file(XCFW_REL)
xcfw_ref.last_known_file_type = 'wrapper.xcframework'

# Attach to Frameworks build phase
fw_phase = target.frameworks_build_phase
unless fw_phase.files_references.include?(xcfw_ref)
  build_file = fw_phase.add_file_reference(xcfw_ref)
  build_file.settings = { 'ATTRIBUTES' => ['CodeSignOnCopy', 'RemoveHeadersOnCopy'] }
end

# Attach to Embed Frameworks build phase (creating it if needed)
embed = target.build_phases.find { |p|
  p.isa == 'PBXCopyFilesBuildPhase' && p.name == 'Embed Frameworks'
}
unless embed
  embed = target.new_copy_files_build_phase('Embed Frameworks')
  embed.symbol_dst_subfolder_spec = :frameworks
end
unless embed.files_references.include?(xcfw_ref)
  bf = embed.add_file_reference(xcfw_ref)
  bf.settings = { 'ATTRIBUTES' => ['CodeSignOnCopy', 'RemoveHeadersOnCopy'] }
end

# Build settings fix-ups:
#  1. Framework search path so the linker finds the XCFramework.
#  2. -ObjC -all_load so every symbol from the *static* archive inside the
#     XCFramework is kept — otherwise the linker dead-strips the whole
#     archive because Dart FFI resolves symbols at runtime and nothing
#     in Swift/ObjC references them statically.
#  3. EXCLUDED_ARCHS=x86_64 for simulator — we only ship arm64-simulator
#     slices in the XCFramework.
target.build_configurations.each do |cfg|
  fws = Array(cfg.build_settings['FRAMEWORK_SEARCH_PATHS']) | ['$(inherited)', '$(PROJECT_DIR)/Frameworks']
  cfg.build_settings['FRAMEWORK_SEARCH_PATHS'] = fws

  # -ObjC -all_load: force-load every object from the static archive
  ldflags = cfg.build_settings['OTHER_LDFLAGS'] || '$(inherited)'
  ldflags = Array(ldflags) unless ldflags.is_a?(Array)
  ldflags |= ['-ObjC', '-all_load']
  cfg.build_settings['OTHER_LDFLAGS'] = ldflags

  # Simulator x86_64 has no slice in our XCFramework (Apple Silicon only)
  cfg.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
end

# Project-level build settings mirror the target ones (Xcode merges them)
project.build_configurations.each do |cfg|
  cfg.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
end

project.save
puts "CryptoLib.xcframework registered with Runner target."
