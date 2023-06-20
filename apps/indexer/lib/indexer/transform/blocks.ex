defmodule Indexer.Transform.Blocks do
  @moduledoc """
  Protocol for transforming blocks.
  """

  @type block :: map()

  @doc """
  Transforms a block.
  """
  @callback transform(block :: block()) :: block()

  @doc """
  Runs a list of blocks through the configured block transformer.
  """
  def transform_blocks(blocks) when is_list(blocks) do
    transformer = Application.get_env(:indexer, :block_transformer)

    Enum.map(blocks, &transformer.transform/1)
  end

  @doc """
  Calculates the signer's address by recovering the ECDSA public key.

  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  """
  def signer(block) when is_map(block) do
    if String.length(block.extra_data) == 196 do
      # Last 65 bytes is the signature. Multiply by two since we haven't transformed to raw bytes
      {extra_data, signature} = String.split_at(trim_prefix(block.extra_data), -130)

      block = %{block | extra_data: extra_data}

      signature_hash = signature_hash(block)

      recover_pub_key(signature_hash, decode(signature))
    else
      {extra_data, encoded_ex_data} = String.split_at(trim_prefix(block.extra_data), 64)

      block = %{block | extra_data: extra_data}

      { hardfork_number, "" } = Integer.parse(Application.get_env(:indexer, :hardfork_number))

      if block.number >= hardfork_number do
        # after hardfork, BLS
        [_ | [ _ | [ [proposer | _ ] | _ ] ]] = ExRLP.decode(decode(encoded_ex_data))

        "0x" <> Base.encode16(proposer, case: :lower)
      else
        # before hardfork, ecdsa secp256k1
        [evList | [ [ round | roundInfo ] | [ proposal | _ ] ]] = ExRLP.decode(decode(encoded_ex_data))

        evHash = calcEvListHash(evList)

        if (length(roundInfo) == 1) do
          [ polRound ] = roundInfo

          signature_hash = reimint_signature_hash(block, round, polRound, evHash)

          recover_pub_key(signature_hash, proposal)
        else
          [ polRound | [ commitRound ] ] = roundInfo

          signature_hash = reimint_signature_hash(block, round, polRound, evHash)

          recover_pub_key(signature_hash, proposal)
        end
      end
    end
  end

  defp calcEvListHash(evList) do
    if length(evList) == 1 do
      [ev1] = evList
      [_ | [ ev1Votes ] ] = ev1

      encodedEv1 = ExRLP.encode(ev1Votes)

      ev1Hash = ExKeccak.hash_256(encodedEv1)

      ev1Hash
    else
      if length(evList) == 2 do
        [ev1 | [ ev2] ] = evList
        [_ | [ ev1Votes ] ] = ev1
        [_ | [ ev2Votes ] ] = ev2

        encodedEv1 = ExRLP.encode(ev1Votes)
        encodedEv2 = ExRLP.encode(ev2Votes)

        ev1Hash = ExKeccak.hash_256(encodedEv1)
        ev2Hash = ExKeccak.hash_256(encodedEv2)

        ev1Hash <> ev2Hash
      else
        <<>>
      end
    end
  end

  # Get EIP-1559 compatible block header
  defp get_header_data(block) do
    header_data = [
      decode(block.parent_hash),
      decode(block.sha3_uncles),
      decode(block.miner_hash),
      decode(block.state_root),
      decode(block.transactions_root),
      decode(block.receipts_root),
      decode(block.logs_bloom),
      block.difficulty,
      block.number,
      block.gas_limit,
      block.gas_used,
      DateTime.to_unix(block.timestamp),
      decode(block.extra_data),
      decode(block.mix_hash),
      decode(block.nonce)
    ]

    if Map.has_key?(block, :base_fee_per_gas) do
      # credo:disable-for-next-line
      header_data ++ [block.base_fee_per_gas]
    else
      header_data
    end
  end

  # Signature hash calculated from the block header.
  # Needed for PoA-based chains
  defp signature_hash(block) do
    header_data = get_header_data(block)

    ExKeccak.hash_256(ExRLP.encode(header_data))
  end

  defp reimint_signature_hash(block, round, polRound, evHash) do
    header_data = [
      decode(block.parent_hash),
      decode(block.sha3_uncles),
      decode(block.miner_hash),
      decode(block.state_root),
      decode(block.transactions_root),
      decode(block.receipts_root),
      decode(block.logs_bloom),
      block.difficulty,
      block.number,
      block.gas_limit,
      block.gas_used,
      DateTime.to_unix(block.timestamp),
      decode(block.extra_data) <> evHash,
      decode(block.mix_hash),
      decode(block.nonce)
    ]

    ExKeccak.hash_256(ExRLP.encode([<<0>>, block.number, round, polRound, ExKeccak.hash_256(ExRLP.encode(header_data))]))
  end

  defp trim_prefix("0x" <> rest), do: rest

  defp decode("0x" <> rest) do
    decode(rest)
  end

  defp decode(data) do
    Base.decode16!(data, case: :mixed)
  end

  # Recovers the key from the signature hash and signature
  defp recover_pub_key(signature_hash, signature) do
    <<
      r::bytes-size(32),
      s::bytes-size(32),
      v::integer-size(8)
    >> = signature

    # First byte represents compression which can be ignored
    # Private key is the last 64 bytes
    {:ok, <<_compression::bytes-size(1), private_key::binary>>} =
      :libsecp256k1.ecdsa_recover_compact(signature_hash, r <> s, :uncompressed, v)

    # Public key comes from the last 20 bytes
    <<_::bytes-size(12), public_key::binary>> = ExKeccak.hash_256(private_key)

    miner_address = Base.encode16(public_key, case: :lower)
    "0x" <> miner_address
  end
end
