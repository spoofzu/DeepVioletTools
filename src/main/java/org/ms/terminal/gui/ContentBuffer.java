package org.ms.terminal.gui;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ContentBuffer {
    private final StringBuilder content = new StringBuilder();
    private final List<ContentListener> listeners = new CopyOnWriteArrayList<>();

    interface ContentListener { void onContentChanged(); }
    public void addListener(ContentListener listener) { listeners.add(listener); }

    public void append(String text) { content.append(text); notifyListeners(); }
    public void append(char ch) { content.append(ch); notifyListeners(); }
    public String getContent() { return content.toString(); }

    public void clear() { content.setLength(0); notifyListeners(); }

    private void notifyListeners() { listeners.forEach(ContentListener::onContentChanged); }
}
