package de.einesel.guardian;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

public record GuardPayload(Type<GuardPayload> type, byte[] bytes) implements CustomPacketPayload {
    public static final int MAX_BYTES = 30000;
    public static final Type<GuardPayload> CHALLENGE = new Type<>(Identifier.fromNamespaceAndPath("guardian", "challenge"));
    public static final Type<GuardPayload> RESPONSE = new Type<>(Identifier.fromNamespaceAndPath("guardian", "response"));

    // Bukkit plugin messages carry raw bytes, with no extra string/array length prefix.
    public static StreamCodec<FriendlyByteBuf, GuardPayload> codec(Type<GuardPayload> type) {
        return new StreamCodec<>() {
            public GuardPayload decode(FriendlyByteBuf buffer) {
                if (buffer.readableBytes() > MAX_BYTES) throw new IllegalArgumentException("Guard payload too large");
                byte[] bytes = new byte[buffer.readableBytes()];
                buffer.readBytes(bytes);
                return new GuardPayload(type, bytes);
            }
            public void encode(FriendlyByteBuf buffer, GuardPayload payload) {
                if (payload.bytes.length > MAX_BYTES) throw new IllegalArgumentException("Guard payload too large");
                buffer.writeBytes(payload.bytes);
            }
        };
    }
}
