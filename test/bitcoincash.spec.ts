import * as assert from 'assert';
import {
  payments,
  networks as NETWORKS,
  Transaction,
  Psbt,
} from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

const ECPair = ECPairFactory(ecc);

describe('Psbt for Bitcoin Cash', function () {
  const network = NETWORKS['testnet'];

  const key = ECPair.fromPrivateKey(Buffer.alloc(32, 1));
  const script = payments.p2pkh({ pubkey: key.publicKey }).output!;
  const parent = new Transaction();
  parent.addInput(Buffer.alloc(32, 3), 0);
  parent.addOutput(script, 100000n);
  const witnessUtxo = { script, value: 100000n };
  const expectedHex =
    '0200000001b603d6c490bacf4f5ed31809fd1b539164f39e45e4f02049c802b63bf152b788000000006a473044022063b3d3c68e546c7b7cf84e10ad9766e3a079153771b540b07990d534f0ccd3ce02200b8a10cf6c7b9d65482096f6bb9204d6ffbaa6c9870a684d62cf362159d741514121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff01b8820100000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000';

  function makePsbt(inputData: Record<string, unknown>): Psbt {
    return new Psbt({ forkCoin: 'bch' })
      .addInput({ hash: parent.getId(), index: 0, ...inputData })
      .addOutput({ script, value: 99000n });
  }

  it('preserves the default BCH forkId signature for all valid UTXO forms', () => {
    [
      { witnessUtxo },
      { nonWitnessUtxo: parent.toBuffer() },
      { nonWitnessUtxo: parent.toBuffer(), witnessUtxo },
    ].forEach(inputData => {
      const psbt = makePsbt(inputData).signInput(0, key);
      assert.strictEqual(
        psbt.data.inputs[0].partialSig![0].signature.at(-1),
        0x41,
      );
      assert.strictEqual(
        psbt.validateSignaturesOfInput(0, (pubkey, hash, signature) =>
          ecc.verify(hash, pubkey, signature),
        ),
        true,
      );
      assert.strictEqual(
        psbt.finalizeAllInputs().extractTransaction().toHex(),
        expectedHex,
      );
      assert.strictEqual(psbt.getFee(), 1000n);
    });
  });

  it('rejects conflicting BCH metadata before producing a signature', () => {
    const psbt = makePsbt({
      nonWitnessUtxo: parent.toBuffer(),
      witnessUtxo: { script, value: 99100n },
    });
    assert.throws(
      () => psbt.signInput(0, key),
      /Witness UTXO .*non-witness UTXO/,
    );
    assert.strictEqual(psbt.data.inputs[0].partialSig, undefined);
  });

  it('rejects missing UTXO metadata on an already signed BCH transaction', () => {
    const psbt = makePsbt({ nonWitnessUtxo: parent.toBuffer() })
      .signInput(0, key)
      .finalizeAllInputs();
    psbt.data.inputs[0] = {
      finalScriptSig: psbt.data.inputs[0].finalScriptSig,
    };
    const parsed = Psbt.fromHex(psbt.toHex(), { forkCoin: 'bch' });
    assert.throws(() => parsed.getFee(), /Need a Utxo input item/);
    assert.throws(() => parsed.getFeeRate(), /Need a Utxo input item/);
    assert.throws(() => parsed.extractTransaction(), /Need a Utxo input item/);
  });
  it('Bitcoin Cash test case 3', function () {
    const value = 50 * 1e8;
    const txid =
      '40c8a218923f23df3692530fa8e475251c50c7d630dccbdfbd92ba8092f4aa13';
    const vout = 0;

    const wif = 'cTNwkxh7nVByhc3i7BH6eaBFQ4yVs6WvXBGBoA9xdKiorwcYVACc';
    const keyPair = ECPair.fromWIF(wif, network);

    const pk = keyPair.publicKey;
    const spk = payments.p2pk({ pubkey: pk }).output!;
    const hashType =
      Transaction.SIGHASH_ALL | Transaction.SIGHASH_BITCOINCASHBIP143;

    // Psbt
    const psbt = new Psbt({ network });
    const hexPsbt = psbt
      .addInput({
        hash: txid,
        index: vout,
        sequence: Transaction.DEFAULT_SEQUENCE,
        witnessUtxo: {
          script: spk,
          value: BigInt(value),
        },
        sighashType: hashType, // This is how you tell Psbt it is forkid!!!
      })
      .addOutput({
        address: 'bchtest:qrxjnnyhsfkrw2q6ccfsrex4a5m5wuzc2c92xdq49x',
        value: BigInt(value),
      })
      .signInput(0, keyPair)
      .finalizeAllInputs()
      .extractTransaction()
      .toHex();

    const result =
      '020000000113aaf49280ba92bddfcbdc30d6c7501c2575e4a80f539236df233f9218a2' +
      'c8400000000049483045022100c5874e39da4dd427d35e24792bf31dcd63c25684deec' +
      '66b426271b4043e21c3002201bfdc0621ad4237e8db05aa6cad69f3d5ab4ae32ebb204' +
      '8f65b12165da6cc69341ffffffff0100f2052a010000001976a914cd29cc97826c3728' +
      '1ac61301e4d5ed374770585688ac00000000';
    assert.equal(result, hexPsbt);
  });
});
