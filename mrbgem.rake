MRuby::Gem::Specification.new('mruby-bpf') do |spec|
  spec.license = 'MIT'
  spec.author  = 'Internet Initiative Japan Inc.'
  spec.cc.include_paths << "#{build.root}/src"
  spec.add_dependency 'mruby-io'
end

