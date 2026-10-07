package cardsnake.issuer;

import com.google.protobuf.ByteString;
import com.payneteasy.tlv.BerTag;
import cardsnake.issuer.helpers.Bytes;
import cardsnake.issuer.model.StoreDataCommand;
import cardsnake.issuer.model.StoreDataResponse;
import cardsnake.issuer.securemessaging.SecureMessagingChannel;
import cardsnake.issuer.securemessaging.SecureMessagingKeyStore;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * One ARMIS personalization of ArmisSnake on one card, run once at install:
 * INTERNAL AUTHENTICATE, PUT DATA player name, PUT DATA player id. When the
 * card has accepted both, the player is registered so that scores the card
 * signs later can be checked (see Scores).
 */
@Slf4j
public class PersonalizationSession {

    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    private static final byte INS_PUT_DATA = (byte) 0xDA;

    private static final BerTag TAG_PLAYER_NAME = new BerTag(0x5F, 0x20);
    private static final BerTag TAG_PLAYER_ID = new BerTag(0xDF, 0x02);

    private final Players players;
    private final Leaderboard leaderboard;
    private final Player player;
    private final SecureMessagingChannel smChannel;

    private int step = 0;

    public PersonalizationSession(@NonNull SecureMessagingKeyStore secureMessagingKeyStore,
                                  @NonNull SecureRandom secureRandom,
                                  @NonNull X509Certificate cardHolderCertificate,
                                  @NonNull Players players,
                                  @NonNull Leaderboard leaderboard) {
        // ARMIS server starts a session only for a valid card holder certificate issued by ARMIS CA
        // with a good OCSP status; see issuer-openapi.yml.
        this.players = players;
        this.leaderboard = leaderboard;
        this.player = Player.of(cardHolderCertificate, secureRandom);
        smChannel = new SecureMessagingChannel(secureMessagingKeyStore, secureRandom, cardHolderCertificate);
    }

    public Optional<StoreDataCommand> startPersonalization() {
        // Ephemeral public key signed with the issuer private key
        return command(false, appletCommand(INS_INTERNAL_AUTHENTICATE, (byte) 0, (byte) 0, smChannel.internalAuthenticate()));
    }

    public Optional<StoreDataCommand> continuePersonalization(StoreDataResponse previous) {
        assertResponseSuccessful(previous);
        byte[] data = previous.getData().toByteArray();
        switch (++step) {
            case 1: {
                smChannel.parseInternalAuthenticateResponseAndPerformKeyAgreement(data);
                byte[] name = player.name().getBytes(StandardCharsets.UTF_8);
                return command(false, appletCommand(INS_PUT_DATA, TAG_PLAYER_NAME,
                        smChannel.wrap(INS_PUT_DATA, name, OptionalInt.empty())));
            }
            case 2: {
                smChannel.unwrap(data, previous.getStatusWord());
                return command(true, appletCommand(INS_PUT_DATA, TAG_PLAYER_ID,
                        smChannel.wrap(INS_PUT_DATA, player.idBytes(), OptionalInt.empty())));
            }
            case 3: {
                smChannel.unwrap(data, previous.getStatusWord());
                // A reinstall replaces the card's earlier player and score
                players.register(player).ifPresent(leaderboard::remove);
                log.info("Personalized '{}' as player {}", player.name(), player.id());
                return Optional.empty();
            }
            default:
                throw new RuntimeException("Issuer finished personalization session, but ARMIS server tried to continue");
        }
    }

    private static byte[] appletCommand(byte ins, BerTag p1p2, byte[] data) {
        return appletCommand(ins, p1p2.bytes[0], p1p2.bytes[1], data);
    }

    private static byte[] appletCommand(byte ins, byte p1, byte p2, byte[] data) {
        byte[] command = Bytes.asArrayOfLength(4 + data.length, ins, p1, p2, (byte) data.length);
        Bytes.copyIntoArray(command, 4, data);
        return command;
    }

    private static void assertResponseSuccessful(StoreDataResponse response) {
        // On a status word other than 9000 the issuer must abort the personalization
        if (response.getStatusWord() != 0x9000) {
            throw new IssuerAbortedPersonalizationException(null);
        }
    }

    private static Optional<StoreDataCommand> command(boolean last, byte[] appletCommand) {
        return Optional.of(new StoreDataCommand(last, true, ByteString.copyFrom(appletCommand)));
    }
}
