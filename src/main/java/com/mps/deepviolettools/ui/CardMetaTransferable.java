package com.mps.deepviolettools.ui;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;

import com.mps.deepviolettools.model.CardMetaElement;

/**
 * Swing {@link Transferable} wrapper for a {@link CardMetaElement},
 * enabling drag-and-drop between the palette and the card preview.
 */
public class CardMetaTransferable implements Transferable {

	/** Custom DataFlavor for CardMetaElement drag-and-drop. */
	public static final DataFlavor FLAVOR = new DataFlavor(CardMetaElement.class,
			"CardMetaElement");

	private final CardMetaElement element;

	public CardMetaTransferable(CardMetaElement element) {
		this.element = element;
	}

	@Override
	public DataFlavor[] getTransferDataFlavors() {
		return new DataFlavor[] { FLAVOR };
	}

	@Override
	public boolean isDataFlavorSupported(DataFlavor flavor) {
		return FLAVOR.equals(flavor);
	}

	@Override
	public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
		if (!FLAVOR.equals(flavor)) {
			throw new UnsupportedFlavorException(flavor);
		}
		return element;
	}
}
