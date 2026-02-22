package com.aegis.android

import com.aegis.android.api.ChatMessage
import com.aegis.android.api.MessageRole
import com.aegis.android.api.sanitizeInput
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/**
 * Unit tests for chat logic.
 *
 * Tests message construction, sanitization, role assignment, and
 * ordering behavior that would live in a ChatViewModel.
 * These tests run on the JVM without Android dependencies.
 */
class ChatViewModelTest {

    // -- Message Construction --

    @Test
    fun test_user_message_creation() {
        val message = ChatMessage(
            id = UUID.randomUUID().toString(),
            role = MessageRole.USER,
            content = "Hello agent",
            agentName = "claude-1",
        )
        assertEquals(MessageRole.USER, message.role)
        assertEquals("Hello agent", message.content)
        assertEquals("claude-1", message.agentName)
        assertTrue(message.timestamp > 0)
    }

    @Test
    fun test_agent_message_creation() {
        val message = ChatMessage(
            id = UUID.randomUUID().toString(),
            role = MessageRole.AGENT,
            content = "I can help with that.",
            agentName = "claude-1",
        )
        assertEquals(MessageRole.AGENT, message.role)
    }

    @Test
    fun test_system_message_creation() {
        val message = ChatMessage(
            id = UUID.randomUUID().toString(),
            role = MessageRole.SYSTEM,
            content = "Agent connected.",
        )
        assertEquals(MessageRole.SYSTEM, message.role)
    }

    @Test
    fun test_message_ids_are_unique() {
        val messages = (1..50).map {
            ChatMessage(
                id = UUID.randomUUID().toString(),
                role = MessageRole.USER,
                content = "msg $it",
            )
        }
        val uniqueIds = messages.map { it.id }.toSet()
        assertEquals(50, uniqueIds.size)
    }

    // -- Message Input Sanitization --

    @Test
    fun test_chat_input_sanitized() {
        assertEquals("hello", sanitizeInput("  hello  "))
        assertEquals("hello", sanitizeInput("hel\u0000lo"))
        assertEquals("", sanitizeInput(""))
        assertEquals("", sanitizeInput("   "))
    }

    @Test
    fun test_chat_input_preserves_unicode() {
        assertEquals("hello world", sanitizeInput("hello world"))
        assertEquals("test 123 !@#", sanitizeInput("test 123 !@#"))
    }

    @Test
    fun test_empty_input_not_sendable() {
        val sanitized = sanitizeInput("")
        assertTrue(sanitized.isEmpty())
    }

    @Test
    fun test_whitespace_only_not_sendable() {
        val sanitized = sanitizeInput("   \t\n  ")
        assertTrue(sanitized.isEmpty())
    }

    // -- Message Ordering --

    @Test
    fun test_messages_ordered_by_timestamp() {
        val messages = listOf(
            ChatMessage("1", MessageRole.USER, "first", timestamp = 100),
            ChatMessage("2", MessageRole.AGENT, "second", timestamp = 200),
            ChatMessage("3", MessageRole.USER, "third", timestamp = 300),
        )
        val sorted = messages.sortedBy { it.timestamp }
        assertEquals("first", sorted[0].content)
        assertEquals("second", sorted[1].content)
        assertEquals("third", sorted[2].content)
    }

    @Test
    fun test_filter_messages_by_agent() {
        val messages = listOf(
            ChatMessage("1", MessageRole.USER, "to agent-1", agentName = "agent-1"),
            ChatMessage("2", MessageRole.AGENT, "from agent-1", agentName = "agent-1"),
            ChatMessage("3", MessageRole.USER, "to agent-2", agentName = "agent-2"),
        )
        val agent1Messages = messages.filter { it.agentName == "agent-1" }
        assertEquals(2, agent1Messages.size)
    }

    // -- Message Content --

    @Test
    fun test_message_content_can_contain_code() {
        val content = "```kotlin\nfun main() { println(\"hello\") }\n```"
        val message = ChatMessage(
            id = "code-msg",
            role = MessageRole.AGENT,
            content = content,
        )
        assertTrue(message.content.contains("```"))
        assertTrue(message.content.contains("kotlin"))
    }

    @Test
    fun test_message_content_can_be_multiline() {
        val content = "Line 1\nLine 2\nLine 3"
        val message = ChatMessage(
            id = "multi-msg",
            role = MessageRole.AGENT,
            content = content,
        )
        assertEquals(3, message.content.lines().size)
    }

    @Test
    fun test_message_content_preserves_markdown() {
        val content = "**bold** and *italic* and `code`"
        val message = ChatMessage(
            id = "md-msg",
            role = MessageRole.AGENT,
            content = content,
        )
        assertTrue(message.content.contains("**bold**"))
        assertTrue(message.content.contains("*italic*"))
        assertTrue(message.content.contains("`code`"))
    }

    // -- Agent Selection Logic --

    @Test
    fun test_switching_agent_clears_context() {
        // Simulate agent switch: messages from old agent should not
        // appear when viewing new agent
        val allMessages = mutableListOf(
            ChatMessage("1", MessageRole.USER, "hello", agentName = "agent-1"),
            ChatMessage("2", MessageRole.AGENT, "hi", agentName = "agent-1"),
        )

        // Switch to agent-2
        val currentAgent = "agent-2"
        val visibleMessages = allMessages.filter { it.agentName == currentAgent }
        assertTrue(visibleMessages.isEmpty())
    }
}
