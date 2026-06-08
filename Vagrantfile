Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"

  config.vm.network "public_network"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 512
    vb.cpus   = 1
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update -q
    apt-get install -y --no-install-recommends gcc make libc6-dev traceroute
  SHELL
end
