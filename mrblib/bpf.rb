class BPF < IO
  def initialize(ifname, buflen=nil)
    super(BPF._sysopen(), "r+")
    self.buffer_length = buflen if buflen
    self.interface = ifname
  end
end
