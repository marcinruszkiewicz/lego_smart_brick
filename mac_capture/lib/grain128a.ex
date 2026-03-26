defmodule Grain128a do
  @moduledoc """
  Grain-128A stream cipher (pre-output keystream only; MAC not implemented).

  Parameters: 128-bit key, 96-bit IV.
  Initialization: NFSR ← key; LFSR ← IV || ones(31) || 0; 256 warm-up clocks
  with pre-output XORed into both feedback functions.

  Taps match the Grain-128A specification (ISO/IEC 29167-13).
  Reference: https://github.com/Noxet/grain128a

  Keystream bit order: first output bit → MSB of first output byte.

  Usage:
    iex> Grain128a.keystream(<<0::128>>, <<0::96>>, 16) |> Base.encode16()
    iex> Grain128a.self_test()
  """

  import Bitwise

  @mask128 (1 <<< 128) - 1

  defp bit(x, i), do: (x >>> i) &&& 1

  defp h(nfsr, lfsr) do
    x0 = bit(nfsr, 12)
    x1 = bit(lfsr, 8)
    x2 = bit(lfsr, 13)
    x3 = bit(lfsr, 20)
    x4 = bit(nfsr, 95)
    x5 = bit(lfsr, 42)
    x6 = bit(lfsr, 60)
    x7 = bit(lfsr, 79)
    x8 = bit(lfsr, 94)

    bxor(bxor(bxor(band(x0, x1), band(x2, x3)), bxor(band(x4, x5), band(x6, x7))),
         band(band(x0, x4), x8))
  end

  defp preoutput_bit(nfsr, lfsr) do
    bxor(
      bxor(
        bxor(h(nfsr, lfsr), bit(lfsr, 93)),
        bxor(bit(nfsr, 2), bit(nfsr, 15))
      ),
      bxor(
        bxor(bit(nfsr, 36), bit(nfsr, 45)),
        bxor(bxor(bit(nfsr, 64), bit(nfsr, 73)), bit(nfsr, 89))
      )
    )
  end

  defp l_feedback(lfsr) do
    bxor(
      bxor(bit(lfsr, 0), bit(lfsr, 7)),
      bxor(bxor(bit(lfsr, 38), bit(lfsr, 70)), bxor(bit(lfsr, 81), bit(lfsr, 96)))
    )
  end

  defp f_feedback(nfsr, lfsr) do
    s0 = bit(lfsr, 0)
    b = fn i -> bit(nfsr, i) end

    t0 = bxor(bxor(b.(0), b.(26)), bxor(b.(56), bxor(b.(91), b.(96))))
    t1 = band(b.(3), b.(67))
    t2 = band(b.(11), b.(13))
    t3 = band(b.(17), b.(18))
    t4 = band(b.(27), b.(59))
    t5 = band(b.(40), b.(48))
    t6 = band(b.(61), b.(65))
    t7 = band(b.(68), b.(84))
    t8 = band(band(b.(22), b.(24)), b.(25))
    t9 = band(band(b.(70), b.(78)), b.(82))
    t10 = band(band(b.(88), b.(92)), band(b.(93), b.(95)))

    fbt = bxor(bxor(bxor(t0, t1), bxor(t2, t3)),
               bxor(bxor(t4, t5), bxor(bxor(t6, t7), bxor(t8, bxor(t9, t10)))))
    bxor(s0, fbt)
  end

  defp shift128(val, new_bit) do
    band(bor(val >>> 1, band(new_bit, 1) <<< 127), @mask128)
  end

  @doc "Load 16-byte key into NFSR (little-endian)."
  def load_nfsr(<<key::little-integer-size(128)>>), do: band(key, @mask128)

  @doc "Load 12-byte IV into LFSR: IV(96) || ones(31) || 0."
  def load_lfsr(<<iv::little-integer-size(96)>>) do
    band(bor(iv, ((1 <<< 31) - 1) <<< 96), @mask128)
  end

  @doc "Initialize Grain-128A state: 256 warm-up clocks with pre-output feedback."
  def init_state(<<_::binary-size(16)>> = key, <<_::binary-size(12)>> = iv) do
    nfsr = load_nfsr(key)
    lfsr = load_lfsr(iv)
    do_init(nfsr, lfsr, 256)
  end

  defp do_init(nfsr, lfsr, 0), do: {nfsr, lfsr}
  defp do_init(nfsr, lfsr, rounds) do
    y = preoutput_bit(nfsr, lfsr)
    ln = bxor(l_feedback(lfsr), y)
    fn_val = bxor(f_feedback(nfsr, lfsr), y)
    do_init(shift128(nfsr, fn_val), shift128(lfsr, ln), rounds - 1)
  end

  @doc """
  Generate `num_bytes` of keystream from an initialized state.
  Returns `{keystream_binary, new_nfsr, new_lfsr}`.
  """
  def keystream_bytes({nfsr, lfsr}, num_bytes) do
    {bits, nfsr2, lfsr2} = generate_bits(nfsr, lfsr, num_bytes * 8, [])
    ks = bits_to_binary(bits)
    {ks, nfsr2, lfsr2}
  end

  defp generate_bits(nfsr, lfsr, 0, acc), do: {Enum.reverse(acc), nfsr, lfsr}
  defp generate_bits(nfsr, lfsr, remaining, acc) do
    y = preoutput_bit(nfsr, lfsr)
    ln = l_feedback(lfsr)
    fn_val = f_feedback(nfsr, lfsr)
    generate_bits(shift128(nfsr, fn_val), shift128(lfsr, ln), remaining - 1, [y | acc])
  end

  defp bits_to_binary(bits) do
    bits
    |> Enum.chunk_every(8, 8, [0, 0, 0, 0, 0, 0, 0])
    |> Enum.map(fn chunk ->
      Enum.reduce(Enum.with_index(chunk), 0, fn {bit_val, j}, acc ->
        bor(acc, bit_val <<< (7 - j))
      end)
    end)
    |> :binary.list_to_bin()
  end

  @doc """
  High-level: generate `num_bytes` of keystream given a 16-byte key and 12-byte IV.

      Grain128a.keystream(key, iv, 32)
  """
  def keystream(key, iv, num_bytes) do
    state = init_state(key, iv)
    {ks, _, _} = keystream_bytes(state, num_bytes)
    binary_part(ks, 0, num_bytes)
  end

  @doc """
  XOR plaintext/ciphertext with Grain-128A keystream.

      Grain128a.xor_stream(key, iv, ciphertext)
  """
  def xor_stream(key, iv, data) do
    ks = keystream(key, iv, byte_size(data))
    :crypto.exor(data, ks)
  end

  @doc "Run self-test to verify the cipher produces deterministic, consistent output."
  def self_test do
    key = :binary.list_to_bin(Enum.to_list(0..15))
    iv = :binary.list_to_bin(Enum.to_list(0..11))

    ks1 = keystream(key, iv, 32)
    ks2 = keystream(key, iv, 32)
    if ks1 != ks2, do: raise("FAIL: same key+IV produced different keystream")

    iv_alt = :binary.list_to_bin(for b <- 0..11, do: Bitwise.bxor(b, 0xFF))
    ks_alt = keystream(key, iv_alt, 32)
    if ks1 == ks_alt, do: raise("FAIL: different IV produced same keystream")

    pt = "Hello grain-128a test block!!"
    ct = :crypto.exor(pt, keystream(key, iv, byte_size(pt)))
    dec = :crypto.exor(ct, keystream(key, iv, byte_size(ct)))
    if dec != pt, do: raise("FAIL: encrypt/decrypt round-trip failed")

    IO.puts("Grain128a.self_test: OK (keystream[0..7] = #{Base.encode16(binary_part(ks1, 0, 8))})")
    :ok
  end
end
